"""Celery entry point for report generation (logic: app/reports/generate.py)."""

import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app.core.logging import get_logger
from app.core.tasks.celery_app import celery_app
from app.core.tasks.loop import reset_loop, run_async
from app.reports.dispatch import GENERATE_REPORT_TASK
from app.reports.generate import generate_report, mark_failed

logger = get_logger("sentinel.worker")


@celery_app.task(name=GENERATE_REPORT_TASK, acks_late=True)
def generate(report_id: str) -> str:
    """Only the id travels in the message; everything else is read from the database."""
    parsed = uuid.UUID(report_id)
    try:
        return run_async(generate_report(parsed))
    except SoftTimeLimitExceeded:
        logger.error("report.celery_soft_limit", report_id=report_id)
        reset_loop()
        run_async(mark_failed(parsed, "render_timeout", "The report took too long to generate."))
        return "FAILED"
