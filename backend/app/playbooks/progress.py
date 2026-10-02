"""Playbook progress snapshots (shared by the orchestrator and the WebSocket relay)."""

from datetime import UTC, datetime

from app.core.runs.events import PlaybookEvent
from app.db.models import PlaybookRun


def playbook_event(run: PlaybookRun) -> PlaybookEvent:
    return PlaybookEvent(
        playbook_run_id=str(run.id),
        status=run.status,
        progress_pct=run.progress_pct,
        current_step=run.current_step,
        steps=[{"step_id": s.step_id, "status": s.status} for s in run.steps],
        ts=datetime.now(UTC).isoformat(),
    )
