"""Startup/shutdown of backing services (12-factor IV & IX).

Tests may pre-populate ``app.state.redis`` / ``app.state.db_engine`` with fakes
before the lifespan runs; anything already present is reused, not replaced.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.infra.rate_limiter import RateLimiter
from app.infra.redis import create_redis

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastapi import FastAPI

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = app.state.settings
    engine = getattr(app.state, "db_engine", None) or create_engine(settings)
    redis = getattr(app.state, "redis", None) or create_redis(settings)

    app.state.db_engine = engine
    app.state.db_sessionmaker = create_session_factory(engine)
    app.state.redis = redis
    app.state.rate_limiter = RateLimiter(redis, fail_open=settings.rate_limit_fail_open)

    await app.state.plugins.startup(app)
    log.info("startup_complete", environment=settings.environment, version=settings.app_version)
    try:
        yield
    finally:
        await app.state.plugins.shutdown(app)
        await redis.aclose()
        await engine.dispose()
        log.info("shutdown_complete")
