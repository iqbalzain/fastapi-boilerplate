"""Fixed-window rate limiter backed by Redis.

``SET NX EX`` guarantees the window key always carries a TTL before the first
``INCR``, so a crash between the two commands can never leave an immortal key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redis.exceptions import RedisError

from app.core.logging import get_logger

if TYPE_CHECKING:
    from redis.asyncio import Redis

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class RateLimiter:
    def __init__(self, redis: Redis, *, fail_open: bool = True, prefix: str = "rl") -> None:
        self._redis = redis
        self._fail_open = fail_open
        self._prefix = prefix

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        redis_key = f"{self._prefix}:{key}"
        try:
            await self._redis.set(redis_key, 0, ex=window_seconds, nx=True)
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.incr(redis_key)
                pipe.ttl(redis_key)
                count, ttl = await pipe.execute()
        except RedisError as exc:
            log.warning("rate_limiter_backend_error", error=str(exc), fail_open=self._fail_open)
            return RateLimitDecision(
                allowed=self._fail_open, limit=limit, remaining=0, retry_after=window_seconds
            )
        retry_after = max(int(ttl), 1) if ttl and ttl > 0 else window_seconds
        remaining = max(limit - int(count), 0)
        return RateLimitDecision(
            allowed=int(count) <= limit, limit=limit, remaining=remaining, retry_after=retry_after
        )
