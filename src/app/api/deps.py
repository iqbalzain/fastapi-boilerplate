"""FastAPI dependencies: the only place request plumbing meets the domain layer.

No ``from __future__ import annotations`` here: FastAPI resolves these signatures at
runtime, so every annotation must be a real object.
"""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ForbiddenError, RateLimitedError, UnauthorizedError
from app.core.security import TokenType, decode_token
from app.db.session import session_scope
from app.infra.rate_limiter import RateLimiter
from app.infra.token_store import TokenDenylist
from app.modules.users.models import User
from app.modules.users.repository import UserRepository

_bearer = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_redis(request: Request) -> Redis:
    return request.app.state.redis  # type: ignore[no-any-return]


def get_rate_limiter(request: Request) -> RateLimiter:
    return request.app.state.rate_limiter  # type: ignore[no-any-return]


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with session_scope(request.app.state.db_sessionmaker) as session:
        yield session


def get_token_denylist(redis: Annotated[Redis, Depends(get_redis)]) -> TokenDenylist:
    return TokenDenylist(redis)


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DbSession = Annotated[AsyncSession, Depends(get_db)]
RedisDep = Annotated[Redis, Depends(get_redis)]
DenylistDep = Annotated[TokenDenylist, Depends(get_token_denylist)]


async def get_current_user(
    request: Request,
    settings: SettingsDep,
    session: DbSession,
    denylist: DenylistDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthorizedError("Missing bearer token.")
    claims = decode_token(settings, credentials.credentials, expected_type=TokenType.access)
    if await denylist.is_revoked(claims.jti):
        raise UnauthorizedError("Token has been revoked.")
    user = await UserRepository(session).get_by_id_str(claims.subject)
    if user is None or not user.is_active:
        raise UnauthorizedError("User is inactive or no longer exists.")
    request.state.access_jti = claims.jti
    request.state.access_exp = claims.expires_at
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def require_superuser(user: CurrentUser) -> User:
    if not user.is_superuser:
        raise ForbiddenError("Superuser privileges required.")
    return user


SuperUser = Annotated[User, Depends(require_superuser)]


class RateLimit:
    """Per-route limiter: ``Depends(RateLimit(5, 60))`` → 5 requests/minute per client IP."""

    def __init__(self, requests: int, window_seconds: int, *, scope: str = "route") -> None:
        self.requests = requests
        self.window_seconds = window_seconds
        self.scope = scope

    async def __call__(
        self, request: Request, limiter: Annotated[RateLimiter, Depends(get_rate_limiter)]
    ) -> None:
        host = request.client.host if request.client else "unknown"
        key = f"{self.scope}:{request.url.path}:{host}"
        decision = await limiter.hit(key, limit=self.requests, window_seconds=self.window_seconds)
        if not decision.allowed:
            raise RateLimitedError(decision.retry_after, "Too many attempts; slow down.")
