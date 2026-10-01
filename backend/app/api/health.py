"""Liveness and readiness probes.

``/health`` (liveness) only proves the process is serving requests. It touches
no dependencies, so a database outage does not make an orchestrator restart a
healthy API in a loop.

``/ready`` (readiness) checks that Postgres and Redis are reachable, each with
a hard timeout. Responses name the failing component but never include error
text: driver errors can leak hostnames, usernames or DSNs (CLAUDE.md rule 8).
"""

import asyncio
import logging
from typing import Annotated, Literal

import asyncpg
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import __version__
from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

CheckStatus = Literal["ok", "fail"]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, CheckStatus]


async def check_postgres(settings: Settings) -> bool:
    timeout = settings.readiness_timeout_seconds
    try:
        conn = await asyncpg.connect(dsn=settings.database_url.get_secret_value(), timeout=timeout)
        try:
            await conn.fetchval("SELECT 1", timeout=timeout)
        finally:
            await conn.close(timeout=timeout)
    # Any failure means "not ready". Only the exception type is logged because
    # its message may contain connection details.
    except Exception as exc:  # noqa: BLE001
        logger.warning("readiness check failed: postgres (%s)", type(exc).__name__)
        return False
    return True


async def check_redis(settings: Settings) -> bool:
    timeout = settings.readiness_timeout_seconds
    client = aioredis.from_url(
        settings.redis_url.get_secret_value(),
        socket_timeout=timeout,
        socket_connect_timeout=timeout,
    )
    try:
        await asyncio.wait_for(client.ping(), timeout=timeout)
    except Exception as exc:  # noqa: BLE001  (same reasoning as check_postgres)
        logger.warning("readiness check failed: redis (%s)", type(exc).__name__)
        return False
    finally:
        await client.aclose()
    return True


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
)
async def ready(settings: Annotated[Settings, Depends(get_settings)]) -> JSONResponse:
    postgres_ok, redis_ok = await asyncio.gather(check_postgres(settings), check_redis(settings))
    checks: dict[str, CheckStatus] = {
        "postgres": "ok" if postgres_ok else "fail",
        "redis": "ok" if redis_ok else "fail",
    }
    all_ok = postgres_ok and redis_ok
    body = ReadinessResponse(status="ready" if all_ok else "not_ready", checks=checks)
    return JSONResponse(status_code=200 if all_ok else 503, content=body.model_dump())
