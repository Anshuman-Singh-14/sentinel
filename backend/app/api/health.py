"""Liveness and readiness probes.

``/health`` (liveness) only proves the process is serving requests. It touches
no dependencies, so a database outage does not make an orchestrator restart a
healthy API in a loop.

``/ready`` (readiness) checks that Postgres and Redis are reachable, each with
a hard timeout. Responses name the failing component but never include error
text: driver errors can leak hostnames, usernames or DSNs (CLAUDE.md rule 8).
"""

import asyncio
from typing import Annotated, Literal

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app import __version__
from app.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.session import get_engine

logger = get_logger("sentinel.health")

router = APIRouter(tags=["health"])

CheckStatus = Literal["ok", "fail"]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, CheckStatus]


async def check_postgres(engine: AsyncEngine, limit_seconds: float) -> bool:
    async def probe() -> None:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(probe(), timeout=limit_seconds)
    # Any failure means "not ready". Only the exception type is logged; the
    # message is still redacted, but type alone is enough to diagnose.
    except Exception as exc:  # noqa: BLE001
        logger.warning("readiness.check_failed", component="postgres", error=type(exc).__name__)
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
        logger.warning("readiness.check_failed", component="redis", error=type(exc).__name__)
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
async def ready(
    settings: Annotated[Settings, Depends(get_settings)],
    engine: Annotated[AsyncEngine, Depends(get_engine)],
) -> JSONResponse:
    postgres_ok, redis_ok = await asyncio.gather(
        check_postgres(engine, settings.readiness_timeout_seconds), check_redis(settings)
    )
    checks: dict[str, CheckStatus] = {
        "postgres": "ok" if postgres_ok else "fail",
        "redis": "ok" if redis_ok else "fail",
    }
    all_ok = postgres_ok and redis_ok
    body = ReadinessResponse(status="ready" if all_ok else "not_ready", checks=checks)
    return JSONResponse(status_code=200 if all_ok else 503, content=body.model_dump())
