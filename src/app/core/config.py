"""Application settings (12-factor III: config lives in the environment).

Every tunable is declared here, typed, validated once at startup, and injected
via :func:`get_settings`. Production enforces stricter invariants so that an
insecure configuration fails fast instead of serving traffic.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIN_SECRET_KEY_LENGTH = 32
_WEAK_SECRET_MARKERS = ("change-me", "changeme", "secret", "password", "example")


class Environment(StrEnum):
    development = "development"
    test = "test"
    staging = "staging"
    production = "production"


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
    )

    # --- identity -----------------------------------------------------------
    app_name: str = "fastapi-boilerplate"
    app_version: str = "0.1.0"
    environment: Environment = Environment.development
    debug: bool = False

    # --- logging ------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["console", "json"] = "console"

    # --- secrets & backing services (12-factor IV) ---------------------------
    secret_key: SecretStr
    database_url: SecretStr = SecretStr("postgresql+asyncpg://app:app@localhost:5432/app")
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_echo: bool = False
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # --- http surface -------------------------------------------------------
    api_prefix: str = "/api/v1"
    docs_enabled: bool | None = None
    cors_allowed_origins: CsvList = Field(default_factory=list)
    trusted_hosts: CsvList = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    max_request_body_bytes: int = Field(default=1_048_576, ge=1024)

    # --- auth ---------------------------------------------------------------
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    jwt_issuer: str = "fastapi-boilerplate"
    jwt_audience: str = "fastapi-boilerplate-clients"
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=300)
    password_min_length: int = Field(default=12, ge=8, le=128)

    # --- cookies & csrf -----------------------------------------------------
    cookie_secure: bool = True
    cookie_domain: str | None = None
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_name: str = "__Host-refresh_token"
    csrf_enabled: bool = True
    csrf_cookie_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-Token"
    csrf_exempt_paths: CsvList = Field(default_factory=list)

    # --- abuse controls -----------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_requests: int = Field(default=120, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    rate_limit_fail_open: bool = True
    rate_limit_exempt_paths: CsvList = Field(default_factory=lambda: ["/health"])
    login_rate_limit_requests: int = Field(default=5, ge=1)
    login_rate_limit_window_seconds: int = Field(default=60, ge=1)

    # --- extensions ---------------------------------------------------------
    plugins: CsvList = Field(default_factory=list)
    sentry_dsn: SecretStr | None = None

    @field_validator(
        "cors_allowed_origins",
        "trusted_hosts",
        "csrf_exempt_paths",
        "rate_limit_exempt_paths",
        "plugins",
        mode="before",
    )
    @classmethod
    def _parse_csv(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("database_url")
    @classmethod
    def _require_async_driver(cls, value: SecretStr) -> SecretStr:
        url = value.get_secret_value()
        if not (url.startswith("postgresql+asyncpg://") or url.startswith("sqlite+aiosqlite://")):
            msg = "DATABASE_URL must use an async driver (postgresql+asyncpg or sqlite+aiosqlite)"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _enforce_production_invariants(self) -> Self:
        if self.environment is not Environment.production:
            return self
        problems: list[str] = []
        secret = self.secret_key.get_secret_value()
        if len(secret) < MIN_SECRET_KEY_LENGTH:
            problems.append(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        if any(marker in secret.lower() for marker in _WEAK_SECRET_MARKERS):
            problems.append("SECRET_KEY looks like a placeholder")
        if self.debug:
            problems.append("DEBUG must be false")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE must be true")
        if self.log_format != "json":
            problems.append("LOG_FORMAT must be json")
        if "*" in self.cors_allowed_origins:
            problems.append("CORS_ALLOWED_ORIGINS may not contain '*'")
        if "*" in self.trusted_hosts:
            problems.append("TRUSTED_HOSTS may not contain '*'")
        if problems:
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.production

    @property
    def docs_are_enabled(self) -> bool:
        if self.docs_enabled is None:
            return not self.is_production
        return self.docs_enabled

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.get_secret_value().startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Tests build :class:`Settings` directly."""
    return Settings()  # populated from env
