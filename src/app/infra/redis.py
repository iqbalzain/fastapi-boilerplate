"""Redis client construction.

``REDIS_URL=memory://`` selects an in-process fake (``fakeredis``, a dev-group
dependency) so the service runs with zero external services during local
development and tests. Production configuration rejects it at boot.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redis.asyncio import Redis

if TYPE_CHECKING:
    from app.core.config import Settings


class InMemoryRedisUnavailableError(RuntimeError):
    """``memory://`` requested but fakeredis is not installed."""


def create_redis(settings: Settings) -> Redis:
    if settings.redis_is_in_memory:
        return _in_memory_redis()
    client: Redis = Redis.from_url(
        settings.redis_url.get_secret_value(),
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )
    return client


def _in_memory_redis() -> Redis:
    try:
        from fakeredis.aioredis import FakeRedis
    except ImportError as exc:  # pragma: no cover - depends on dev group
        msg = (
            "REDIS_URL=memory:// needs the 'fakeredis' dev dependency: "
            "run `uv sync --all-groups`, or point REDIS_URL at a real Redis."
        )
        raise InMemoryRedisUnavailableError(msg) from exc
    client: Redis = FakeRedis(decode_responses=True)
    return client
