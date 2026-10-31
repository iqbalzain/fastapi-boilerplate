"""Shared fixtures: isolated app per test with SQLite + fakeredis."""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis.aioredis
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.core.config import Environment, Settings
from app.db.base import Base
from app.db.session import create_engine
from app.main import create_app

TEST_SECRET = "unit-test-signing-key-that-is-long-enough-0123456789abcdef"


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "secret_key": SecretStr(TEST_SECRET),
        "environment": Environment.test,
        "database_url": SecretStr("sqlite+aiosqlite:///:memory:"),
        "redis_url": SecretStr("redis://unused:6379/0"),
        "cookie_secure": False,
        "log_format": "console",
        "trusted_hosts": ["testserver", "localhost"],
        "cors_allowed_origins": ["http://frontend.test"],
        "rate_limit_requests": 1000,
        "docs_enabled": True,
    }
    base.update(overrides)
    return Settings.model_validate(base)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


async def build_app(settings: Settings) -> FastAPI:
    app = create_app(settings)
    engine = create_engine(settings)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app.state.db_engine = engine
    app.state.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return app


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    application = await build_app(settings)
    async with LifespanManager(application):
        yield application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest.fixture
def api(settings: Settings) -> str:
    return settings.api_prefix


USER_EMAIL = "alice@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


async def register(client: AsyncClient, api: str, email: str = USER_EMAIL) -> dict[str, object]:
    resp = await client.post(
        f"{api}/users",
        json={"email": email, "password": USER_PASSWORD, "full_name": "Alice"},
        headers={"Authorization": "Bearer none"},  # bearer header exempts CSRF for API clients
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


async def login(client: AsyncClient, api: str, email: str = USER_EMAIL) -> str:
    resp = await client.post(
        f"{api}/auth/login",
        json={"email": email, "password": USER_PASSWORD},
        headers={"Authorization": "Bearer none"},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])
