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
