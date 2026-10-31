from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.exceptions import UnauthorizedError
from app.core.security import (
    TokenType,
    create_token,
    decode_token,
    hash_password,
    new_csrf_token,
    sign_value,
    verify_password,
    verify_signed_value,
)


def test_password_roundtrip_and_dummy_path():
    hashed = hash_password("hunter2hunter2")
    assert hashed != "hunter2hunter2"
    assert verify_password("hunter2hunter2", hashed) == (True, None)
    assert verify_password("wrong", hashed)[0] is False
    assert verify_password("anything", None) == (False, None)


def test_token_roundtrip(settings):
    issued = create_token(
        settings, subject="u1", token_type=TokenType.access, ttl=timedelta(minutes=5)
    )
    claims = decode_token(settings, issued.token, expected_type=TokenType.access)
    assert claims.subject == "u1"
    assert claims.jti == issued.jti
    assert claims.expires_at == issued.expires_at.replace(microsecond=0)


def test_token_type_confusion_rejected(settings):
    refresh = create_token(
        settings, subject="u1", token_type=TokenType.refresh, ttl=timedelta(days=1)
    )
    with pytest.raises(UnauthorizedError, match="type mismatch"):
        decode_token(settings, refresh.token, expected_type=TokenType.access)


def test_expired_and_tampered_tokens_rejected(settings):
    past = datetime.now(UTC) - timedelta(hours=2)
    expired = create_token(
        settings, subject="u1", token_type=TokenType.access, ttl=timedelta(minutes=1), now=past
    )
    with pytest.raises(UnauthorizedError, match="expired"):
        decode_token(settings, expired.token, expected_type=TokenType.access)

    forged = jwt.encode({"sub": "u1", "typ": "access"}, "other-key", algorithm="HS256")
    with pytest.raises(UnauthorizedError, match="invalid"):
        decode_token(settings, forged, expected_type=TokenType.access)


def test_wrong_audience_rejected(settings):
    other = settings.model_copy(update={"jwt_audience": "someone-else"})
    issued = create_token(
        other, subject="u1", token_type=TokenType.access, ttl=timedelta(minutes=5)
    )
    with pytest.raises(UnauthorizedError):
        decode_token(settings, issued.token, expected_type=TokenType.access)


def test_signed_values(settings):
    token = new_csrf_token(settings)
    assert verify_signed_value(settings, token)
    assert not verify_signed_value(settings, token[:-1] + ("0" if token[-1] != "0" else "1"))
    assert not verify_signed_value(settings, "no-signature")
    assert not verify_signed_value(settings, sign_value(settings, "x").replace("x.", "y."))
