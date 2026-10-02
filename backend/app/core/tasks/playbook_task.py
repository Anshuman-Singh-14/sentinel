"""Celery entry point for playbook runs (orchestrator: app/playbooks/engine.py)."""

import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app.core.logging import get_logger
from app.core.tasks.celery_app import celery_app
from app.core.tasks.loop import reset_loop, run_async
from app.playbooks.dispatch import RUN_PLAYBOOK_TASK
from app.playbooks.engine import execute_playbook, mark_timed_out

logger = get_logger("sentinel.worker")


@celery_app.task(name=RUN_PLAYBOOK_TASK, acks_late=True)
def run_playbook(playbook_run_id: str) -> str:
    """Only the id travels in the message; everything else is read from the database."""
    parsed = uuid.UUID(playbook_run_id)
    try:
        return run_async(execute_playbook(parsed))
    except SoftTimeLimitExceeded:
        logger.error("playbook.celery_soft_limit", playbook_run_id=playbook_run_id)
        reset_loop()
        run_async(mark_timed_out(parsed))
        return "TIMED_OUT"
