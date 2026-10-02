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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from app.config import get_settings
from app.core.logging import get_logger
from app.core.runs import events
from app.db.models import ToolRun
from app.db.session import get_sessionmaker
from app.engine.schemas import RunStatus

logger = get_logger("sentinel.realtime")
router = APIRouter()

MAX_CONNECTION_SECONDS = 30 * 60
DB_RESYNC_SECONDS = 5.0
PING_SECONDS = 20.0


async def _snapshot(run_id: uuid.UUID) -> events.RunEvent | None:
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
        )


def _is_terminal(status_value: str) -> bool:
    return RunStatus(status_value).is_terminal


@router.websocket("/ws/runs/{run_id}")
async def run_updates(websocket: WebSocket, run_id: uuid.UUID, ticket: str = "") -> None:
    settings = get_settings()
    origin = websocket.headers.get("origin")
    # Browsers always send Origin on a WebSocket handshake; non-browser
    # clients carry no ambient cookies, and the ticket is required regardless.
    if origin is not None and origin not in settings.cors_origins:
        logger.warning("ws.rejected", reason="origin")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    grant = await events.redeem_ws_ticket(ticket)
    if grant is None or grant.run_id != str(run_id):
        logger.warning("ws.rejected", reason="ticket")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    pubsub = events.get_redis().pubsub()
    await pubsub.subscribe(events.run_channel(run_id))
    started = time.monotonic()
    try:
        snapshot = await _snapshot(run_id)
        if snapshot is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.send_text(snapshot.to_json())
        if _is_terminal(snapshot.status):
            await websocket.close()
            return

        last_resync = time.monotonic()
        last_ping = time.monotonic()
        while time.monotonic() - started < MAX_CONNECTION_SECONDS:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and isinstance(message.get("data"), str):
                data = message["data"]
                await websocket.send_text(data)
                if _is_terminal(json.loads(data).get("status", "RUNNING")):
                    break
            now = time.monotonic()
            if now - last_resync >= DB_RESYNC_SECONDS:
                last_resync = now
                snapshot = await _snapshot(run_id)
                if snapshot is not None and _is_terminal(snapshot.status):
                    await websocket.send_text(snapshot.to_json())
                    break
            if now - last_ping >= PING_SECONDS:
                last_ping = now
                await websocket.send_text('{"type":"ping"}')
        await websocket.close()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws.relay_failed", run_id=str(run_id))
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe()
            await pubsub.aclose()  # type: ignore[no-untyped-call]
        await asyncio.sleep(0)
