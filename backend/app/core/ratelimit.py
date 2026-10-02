"""Fixed-window rate limiting on Redis (04-security.md section 7, ADR 0003).

Chosen over slowapi: slowapi is decorator-based, requires a ``request``
parameter on every endpoint and is thinly maintained. This module is ~60 lines
on the Redis client the project already uses, and is called explicitly where a
limit applies, so each limit is visible at the call site.

Algorithm: ``INCR key`` then ``EXPIRE key window NX`` in one pipeline
(MULTI/EXEC). The first hit in a window creates the key with its expiry;
later hits only increment it. Fixed windows allow up to 2x the limit across a
window boundary, which is acceptable for brute-force protection.

Failure mode: if Redis is unreachable the limiter raises ``ServiceUnavailable``
(fail closed). Login is the main user, and silently dropping brute-force
protection would be worse than a brief outage.
"""

import time
from dataclasses import dataclass
from typing import Protocol

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.config import get_settings
from app.core.errors import RateLimited, ServiceUnavailable
from app.core.logging import get_logger

logger = get_logger("sentinel.ratelimit")

KEY_PREFIX = "sentinel:ratelimit:"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    limit: int
    retry_after: int


class RateLimiter(Protocol):
    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult: ...


class RedisRateLimiter:
    def __init__(self, client: aioredis.Redis) -> None:
        self._client = client

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        full_key = KEY_PREFIX + key
        try:
            async with self._client.pipeline(transaction=True) as pipe:
                pipe.incr(full_key)
                pipe.expire(full_key, window_seconds, nx=True)
                pipe.ttl(full_key)
                count, _, ttl = await pipe.execute()
        except RedisError as exc:
            logger.error("ratelimit.unavailable", error=type(exc).__name__)
            raise ServiceUnavailable from exc
        retry_after = ttl if isinstance(ttl, int) and ttl > 0 else window_seconds
        return RateLimitResult(count <= limit, int(count), limit, retry_after)


class MemoryRateLimiter:
    """In-process limiter with the same semantics, for unit tests."""

    def __init__(self) -> None:
        self._windows: dict[str, tuple[float, int]] = {}

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.monotonic()
        started, count = self._windows.get(key, (now, 0))
        if now - started >= window_seconds:
            started, count = now, 0
        count += 1
        self._windows[key] = (started, count)
        retry_after = max(1, int(window_seconds - (now - started)))
        return RateLimitResult(count <= limit, count, limit, retry_after)


def raise_if_limited(result: RateLimitResult) -> None:
    if not result.allowed:
        raise RateLimited(headers={"Retry-After": str(result.retry_after)})


_client: aioredis.Redis | None = None


def get_rate_limiter() -> RateLimiter:
    """FastAPI dependency. The Redis client (and its pool) is created once per process."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = aioredis.from_url(
            settings.redis_url.get_secret_value(),
            socket_timeout=settings.readiness_timeout_seconds,
            socket_connect_timeout=settings.readiness_timeout_seconds,
        )
    return RedisRateLimiter(_client)


async def close_rate_limiter() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None
