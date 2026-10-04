"""Shared plumbing for tools that call third-party APIs (NVD, threat intel).

* ``RedisCache``: a JSON-string cache with a TTL. Values are JSON, never
  pickle (CLAUDE.md rule 1).
* ``RedisWindowLimiter``: a fixed request window shared by every worker
  process, so all workers together stay under a provider's rate limit.

Tools receive these through small protocols (``Cache``, ``WindowLimiter``),
so their logic is unit-tested with in-memory fakes.
"""

from typing import Protocol

from app.core.runs.events import get_redis


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...


class WindowLimiter(Protocol):
    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        """0 if a request may go now, else seconds until the window resets."""
        ...


class RedisCache:
    async def get(self, key: str) -> str | None:
        value = await get_redis().get(key)
        return str(value) if value is not None else None

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        await get_redis().set(key, value, ex=ttl_seconds)


class RedisWindowLimiter:
    """Fixed window shared by every worker process.

    A request that does not fit is handed back (DECR), so waiting callers do
    not use up the next window's quota just by asking.
    """

    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        redis = get_redis()
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            pipe.ttl(key)
            count, _, ttl = await pipe.execute()
        if int(count) <= limit:
            return 0.0
        await redis.decr(key)
        return float(ttl if isinstance(ttl, int) and ttl > 0 else window_seconds)
