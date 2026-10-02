"""Run events over Redis: progress pub/sub, cancel flags and WebSocket tickets.

Channel and key layout (all under the ``sentinel:`` prefix):

* ``sentinel:run:{run_id}`` (pub/sub): the worker publishes a JSON snapshot
  of the run's status and progress on every change. The API relays it to
  WebSocket clients. Pub/sub is fire-and-forget, so the database remains the
  source of truth and clients always start from a database snapshot.
* ``sentinel:run:{run_id}:cancel``: set by the API, polled by the tool between
  units of work (cooperative cancellation).
* ``sentinel:ws-ticket:{sha256}``: single-use WebSocket ticket (T12).

The Redis client is created lazily, once per process *and event loop*: the
API has one loop; each Celery worker process has its own (see tool_task).
"""

import asyncio
import hashlib
import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from app.config import get_settings

CANCEL_FLAG_TTL_SECONDS = 24 * 3600

_client: aioredis.Redis | None = None
_client_loop: asyncio.AbstractEventLoop | None = None


def get_redis() -> aioredis.Redis:
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    if _client is None or _client_loop is not loop:
        settings = get_settings()
        _client = aioredis.from_url(
            settings.redis_url.get_secret_value(),
            socket_timeout=5,
            socket_connect_timeout=settings.readiness_timeout_seconds,
            decode_responses=True,
        )
        _client_loop = loop
    return _client


async def close_redis() -> None:
    global _client, _client_loop
    if _client is not None:
        await _client.aclose()
    _client = None
    _client_loop = None


def forget_client() -> None:
    """Abandon the client (its loop is being discarded; see tasks.loop)."""
    global _client, _client_loop
    _client = None
    _client_loop = None


def run_channel(run_id: uuid.UUID) -> str:
    return f"sentinel:run:{run_id}"


def cancel_key(run_id: uuid.UUID) -> str:
    return f"sentinel:run:{run_id}:cancel"


def _ticket_key(ticket: str) -> str:
    # Only the digest is stored, like session tokens (ADR 0003).
    return f"sentinel:ws-ticket:{hashlib.sha256(ticket.encode()).hexdigest()}"


@dataclass(frozen=True, slots=True)
class RunEvent:
    """A snapshot of the parts of a run that change while it executes."""

    run_id: str
    status: str
    progress_pct: int
    progress_message: str | None
    finding_count: int
    max_severity: str | None
    ts: str

    @classmethod
    def now(
        cls,
        run_id: uuid.UUID,
        status: str,
        *,
        progress_pct: int = 0,
        progress_message: str | None = None,
        finding_count: int = 0,
        max_severity: str | None = None,
    ) -> "RunEvent":
        return cls(
            run_id=str(run_id),
            status=status,
            progress_pct=progress_pct,
            progress_message=progress_message,
            finding_count=finding_count,
            max_severity=max_severity,
            ts=datetime.now(UTC).isoformat(),
        )

    def to_json(self) -> str:
        return json.dumps({"type": "run.update", **asdict(self)})


async def publish(event: RunEvent, client: aioredis.Redis | None = None) -> None:
    await (client or get_redis()).publish(run_channel(uuid.UUID(event.run_id)), event.to_json())


async def request_cancel(run_id: uuid.UUID, client: aioredis.Redis | None = None) -> None:
    await (client or get_redis()).set(cancel_key(run_id), "1", ex=CANCEL_FLAG_TTL_SECONDS)


async def is_cancel_requested(run_id: uuid.UUID, client: aioredis.Redis | None = None) -> bool:
    return bool(await (client or get_redis()).exists(cancel_key(run_id)))


@dataclass(frozen=True, slots=True)
class TicketGrant:
    user_id: str
    run_id: str


async def issue_ws_ticket(
    user_id: uuid.UUID, run_id: uuid.UUID, ttl_seconds: int, client: aioredis.Redis | None = None
) -> str:
    ticket = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": str(user_id), "run_id": str(run_id)})
    await (client or get_redis()).set(_ticket_key(ticket), payload, ex=ttl_seconds)
    return ticket


async def redeem_ws_ticket(ticket: str, client: aioredis.Redis | None = None) -> TicketGrant | None:
    """Atomically fetch and delete a ticket: a second use always fails."""
    if not ticket or len(ticket) > 128:
        return None
    raw: Any = await (client or get_redis()).getdel(_ticket_key(ticket))
    if not raw:
        return None
    data = json.loads(raw)
    return TicketGrant(user_id=str(data["user_id"]), run_id=str(data["run_id"]))
