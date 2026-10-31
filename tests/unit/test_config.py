import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Environment, Settings
from tests.conftest import make_settings


def test_csv_fields_accept_comma_separated_strings():
    s = make_settings(cors_allowed_origins="https://a.test, https://b.test", plugins="")
    assert s.cors_allowed_origins == ["https://a.test", "https://b.test"]
    assert s.plugins == []


def test_docs_default_off_in_production_on_elsewhere():
    assert make_settings(docs_enabled=None).docs_are_enabled is True
    prod = make_settings(
        docs_enabled=None,
        environment=Environment.production,
        cookie_secure=True,
        log_format="json",
        database_url=SecretStr("postgresql+asyncpg://u:p@db/app"),
    )
    assert prod.docs_are_enabled is False


def test_production_rejects_weak_configuration():
    with pytest.raises(ValidationError, match="SECRET_KEY looks like a placeholder"):
        make_settings(
            environment=Environment.production,
            secret_key=SecretStr("change-me-" + "x" * 40),
            cookie_secure=True,
            log_format="json",
        )
    with pytest.raises(ValidationError, match="COOKIE_SECURE must be true"):
        make_settings(environment=Environment.production, cookie_secure=False, log_format="json")


def test_database_url_requires_async_driver():
    with pytest.raises(ValidationError, match="async driver"):
        make_settings(database_url=SecretStr("postgresql://app:app@localhost/app"))


def test_settings_are_frozen(settings: Settings):
    with pytest.raises(ValidationError):
        settings.debug = True  # type: ignore[misc]


def test_redis_url_scheme_validation():
    assert make_settings(redis_url=SecretStr("memory://")).redis_is_in_memory
    assert make_settings(redis_url=SecretStr("rediss://host:6380/0")).redis_is_in_memory is False
    with pytest.raises(ValidationError, match="REDIS_URL must start with"):
        make_settings(redis_url=SecretStr("http://localhost"))


def test_production_rejects_dev_only_backends():
    base = {"environment": Environment.production, "cookie_secure": True, "log_format": "json"}
    with pytest.raises(ValidationError, match="SQLite is for local development"):
        make_settings(**base, database_url=SecretStr("sqlite+aiosqlite:///./dev.db"))
    with pytest.raises(ValidationError, match="memory:// is for local development"):
        make_settings(
            **base,
            database_url=SecretStr("postgresql+asyncpg://u:p@db/app"),
            redis_url=SecretStr("memory://"),
        )


def test_refresh_cookie_gets_secure_prefix_only_over_https():
    assert make_settings(cookie_secure=False).effective_refresh_cookie_name == "refresh_token"
    assert (
        make_settings(cookie_secure=True).effective_refresh_cookie_name == "__Secure-refresh_token"
    )
