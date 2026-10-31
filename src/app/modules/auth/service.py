"""Token issuance, rotation and revocation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from app.core.exceptions import UnauthorizedError
from app.core.security import IssuedToken, TokenType, create_token, decode_token

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.infra.token_store import TokenDenylist


@dataclass(frozen=True, slots=True)
class TokenPair:
    access: IssuedToken
    refresh: IssuedToken


class AuthService:
    def __init__(self, settings: Settings, denylist: TokenDenylist) -> None:
        self.settings = settings
        self.denylist = denylist

    def issue_pair(self, user_id: str) -> TokenPair:
        s = self.settings
        return TokenPair(
            access=create_token(
                s,
                subject=user_id,
                token_type=TokenType.access,
                ttl=timedelta(seconds=s.access_token_ttl_seconds),
            ),
            refresh=create_token(
                s,
                subject=user_id,
                token_type=TokenType.refresh,
                ttl=timedelta(seconds=s.refresh_token_ttl_seconds),
            ),
        )

    async def rotate(self, refresh_token: str) -> TokenPair:
        """Validate a refresh token, burn it, and mint a fresh pair."""
        claims = decode_token(self.settings, refresh_token, expected_type=TokenType.refresh)
        if await self.denylist.is_revoked(claims.jti):
            raise UnauthorizedError("Refresh token has been revoked.")
        await self.denylist.revoke(claims.jti, _seconds_until(claims.expires_at))
        return self.issue_pair(claims.subject)

    async def revoke_refresh(self, refresh_token: str | None) -> None:
        if not refresh_token:
            return
        try:
            claims = decode_token(self.settings, refresh_token, expected_type=TokenType.refresh)
        except UnauthorizedError:
            return  # already invalid; nothing to burn
        await self.denylist.revoke(claims.jti, _seconds_until(claims.expires_at))

    async def revoke_access(self, jti: str, expires_at: datetime) -> None:
        await self.denylist.revoke(jti, _seconds_until(expires_at))


def _seconds_until(moment: datetime) -> int:
    return max(int((moment - datetime.now(UTC)).total_seconds()), 1)
