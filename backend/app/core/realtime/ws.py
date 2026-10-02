"""Live run updates: Redis pub/sub -> WebSocket (threat model T12).

Authentication of the handshake, in order:

1. **Origin allowlist.** Browsers always send Origin on WebSocket handshakes
   and pages cannot forge it. Rejecting foreign origins stops Cross-Site
   WebSocket Hijacking, where another site opens a socket that rides on the
   victim's cookies.
2. **Single-use ticket.** Obtained by ``POST /runs/{id}/ws-ticket`` (an
   authenticated, CSRF-checked request), valid for seconds, bound to one user
   and one run, and deleted on first use (``GETDEL``). A leaked URL is useless.

Delivery: the handler subscribes to the run's channel *before* reading the
database snapshot, so an update published in between is not lost. Pub/sub is
best effort; a slow periodic re-read of the database covers dropped messages.
The socket closes once the run reaches a terminal state, or after a hard
lifetime cap.
"""

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.core.logging import get_logger
from app.core.runs import events
from app.db.models import PlaybookRun, ToolRun
from app.db.session import get_sessionmaker
from app.playbooks.progress import playbook_event

logger = get_logger("sentinel.realtime")
router = APIRouter()

MAX_CONNECTION_SECONDS = 30 * 60
DB_RESYNC_SECONDS = 5.0
PING_SECONDS = 20.0


TERMINAL = frozenset({"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"})

Snapshot = Callable[[uuid.UUID], Awaitable[str | None]]  # JSON with a "status" field


async def _run_snapshot(run_id: uuid.UUID) -> str | None:
    async with get_sessionmaker()() as db:
        run = await db.scalar(select(ToolRun).where(ToolRun.id == run_id))
        if run is None:
            return None
        return events.RunEvent.now(
            run.id,
            run.status,
            progress_pct=run.progress_pct,
            progress_message=run.progress_message,
            finding_count=run.finding_count,
            max_severity=run.max_severity,
        ).to_json()


async def _playbook_snapshot(playbook_run_id: uuid.UUID) -> str | None:
    async with get_sessionmaker()() as db:
        run = await db.scalar(
            select(PlaybookRun)
            .where(PlaybookRun.id == playbook_run_id)
            .options(selectinload(PlaybookRun.steps))
        )
        if run is None:
            return None
        return playbook_event(run).to_json()


def _is_terminal(payload: str) -> bool:
    try:
        return json.loads(payload).get("status") in TERMINAL
    except (ValueError, AttributeError):
        return False


async def _relay(
    websocket: WebSocket,
    resource_id: uuid.UUID,
    ticket: str,
    *,
    kind: str,
    channel: str,
    snapshot: Snapshot,
) -> None:
    settings = get_settings()
    origin = websocket.headers.get("origin")
    # Browsers always send Origin on a WebSocket handshake; non-browser
    # clients carry no ambient cookies, and the ticket is required regardless.
    if origin is not None and origin not in settings.cors_origins:
        logger.warning("ws.rejected", reason="origin", kind=kind)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    grant = await events.redeem_ws_ticket(ticket)
    # The ticket must be for this exact resource *and* this kind of stream.
    if grant is None or grant.run_id != str(resource_id) or grant.kind != kind:
        logger.warning("ws.rejected", reason="ticket", kind=kind)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    pubsub = events.get_redis().pubsub()
    # Subscribe before reading the snapshot, so an update in between is not lost.
    await pubsub.subscribe(channel)
    started = time.monotonic()
    try:
        current = await snapshot(resource_id)
        if current is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.send_text(current)
        if _is_terminal(current):
            await websocket.close()
            return

        last_resync = time.monotonic()
        last_ping = time.monotonic()
        while time.monotonic() - started < MAX_CONNECTION_SECONDS:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and isinstance(message.get("data"), str):
                data = message["data"]
                await websocket.send_text(data)
                if _is_terminal(data):
                    break
            now = time.monotonic()
            if now - last_resync >= DB_RESYNC_SECONDS:
                # Pub/sub is best effort: re-read the database now and then.
                last_resync = now
                current = await snapshot(resource_id)
                if current is not None and _is_terminal(current):
                    await websocket.send_text(current)
                    break
            if now - last_ping >= PING_SECONDS:
                last_ping = now
                await websocket.send_text('{"type":"ping"}')
        await websocket.close()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws.relay_failed", kind=kind, resource_id=str(resource_id))
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe()
            await pubsub.aclose()  # type: ignore[no-untyped-call]
        await asyncio.sleep(0)


@router.websocket("/ws/runs/{run_id}")
async def run_updates(websocket: WebSocket, run_id: uuid.UUID, ticket: str = "") -> None:
    await _relay(
        websocket,
        run_id,
        ticket,
        kind="run",
        channel=events.run_channel(run_id),
        snapshot=_run_snapshot,
    )


@router.websocket("/ws/playbooks/{playbook_run_id}")
async def playbook_updates(
    websocket: WebSocket, playbook_run_id: uuid.UUID, ticket: str = ""
) -> None:
    await _relay(
        websocket,
        playbook_run_id,
        ticket,
        kind="playbook",
        channel=events.playbook_channel(playbook_run_id),
        snapshot=_playbook_snapshot,
    )
