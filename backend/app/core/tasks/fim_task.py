"""Celery entry point for scheduled FIM checks (logic: app/fim/schedule.py, ADR 0015)."""

from app.core.tasks.celery_app import celery_app
from app.core.tasks.loop import run_async
from app.core.tasks.tool_task import _ensure_tools
from app.fim.schedule import DISPATCH_TASK, dispatch_due


@celery_app.task(name=DISPATCH_TASK, soft_time_limit=50, time_limit=55)
def dispatch_scheduled() -> int:
    """Sent by beat every minute. Starts the due checks; returns how many were started."""
    _ensure_tools()  # the check tool must be registered before RunService can find it
    return len(run_async(dispatch_due()))
