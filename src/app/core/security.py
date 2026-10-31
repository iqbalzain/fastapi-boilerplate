"""Password hashing and JWT primitives.

* Passwords: Argon2id via pwdlib (memory-hard, OWASP recommended). Hashes are
  transparently upgraded when parameters change (``verify_password`` returns a
  fresh hash when a rehash is needed).
* Tokens: short-lived access tokens + rotating refresh tokens. Every token has
  ``jti`` so it can be revoked, ``typ`` so a refresh token can never be replayed
  as an access token, and ``iss``/``aud`` so tokens minted for another service
  are rejected.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.exceptions import UnauthorizedError

if TYPE_CHECKING:
    from app.core.config import Settings

_password_hash = PasswordHash((Argon2Hasher(),))

# Hash of a throwaway password used to equalise timing when a user does not exist.
_DUMMY_HASH = _password_hash.hash(secrets.token_urlsafe(32))


class TokenType(StrEnum):
    access = "access"
    refresh = "refresh"


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: str
    jti: str
    token_type: TokenType
    expires_at: datetime


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, hashed: str | None) -> tuple[bool, str | None]:
    """Return ``(is_valid, new_hash_if_rehash_needed)``.

    When ``hashed`` is ``None`` (unknown user) we still perform a full verify
    against a dummy hash so response timing does not reveal account existence.
    """
    if hashed is None:
        _password_hash.verify(password, _DUMMY_HASH)
        return False, None
    valid, new_hash = _password_hash.verify_and_update(password, hashed)
    return valid, new_hash


def create_token(
    settings: Settings,
    *,
    subject: str,
    token_type: TokenType,
    ttl: timedelta,
    now: datetime | None = None,
) -> IssuedToken:
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + ttl
    jti = uuid.uuid4().hex
    payload: dict[str, Any] = {
        "sub": subject,
        "jti": jti,
        "typ": token_type.value,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(
        payload, settings.secret_key.get_secret_value(), algorithm=settings.jwt_algorithm
    )
    return IssuedToken(token=token, jti=jti, expires_at=expires_at)


def decode_token(settings: Settings, token: str, *, expected_type: TokenType) -> TokenClaims:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise UnauthorizedError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise UnauthorizedError("Token is invalid.") from exc

    if payload.get("typ") != expected_type.value:
        raise UnauthorizedError("Token type mismatch.")
    return TokenClaims(
        subject=str(payload["sub"]),
        jti=str(payload["jti"]),
        token_type=expected_type,
        expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
    )


def sign_value(settings: Settings, value: str) -> str:
    """HMAC a value with the app secret; used for CSRF tokens."""
    digest = hmac.new(
        settings.secret_key.get_secret_value().encode(), value.encode(), "sha256"
    ).hexdigest()
    return f"{value}.{digest}"


def verify_signed_value(settings: Settings, signed: str) -> bool:
    value, _, digest = signed.rpartition(".")
    if not value or not digest:
        return False
    expected = sign_value(settings, value)
    return hmac.compare_digest(expected, signed)


def new_csrf_token(settings: Settings) -> str:
    return sign_value(settings, secrets.token_urlsafe(32))
