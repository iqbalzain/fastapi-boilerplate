"""Denylist for revoked JWT identifiers (``jti``).

Entries expire together with the token they shadow, so the set stays bounded.
Fail-closed: if Redis is unreachable we treat tokens as revoked, because the
alternative is honouring a token the user explicitly logged out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redis.exceptions import RedisError

from app.core.exceptions import ServiceUnavailableError
from app.core.logging import get_logger

if TYPE_CHECKING:
    from redis.asyncio import Redis

log = get_logger(__name__)


class TokenDenylist:
    def __init__(self, redis: Redis, *, prefix: str = "revoked") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, jti: str) -> str:
        return f"{self._prefix}:{jti}"

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        try:
            await self._redis.set(self._key(jti), 1, ex=max(ttl_seconds, 1))
        except RedisError as exc:
            log.error("token_revoke_failed", error=str(exc))
            raise ServiceUnavailableError("Token store unavailable.") from exc

    async def is_revoked(self, jti: str) -> bool:
        try:
            return bool(await self._redis.exists(self._key(jti)))
        except RedisError as exc:
            log.error("token_lookup_failed", error=str(exc))
            raise ServiceUnavailableError("Token store unavailable.") from exc
