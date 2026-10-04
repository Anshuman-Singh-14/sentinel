"""Hand a report to the workers. The API only needs the task name."""

import uuid
from typing import Protocol

from app.core.tasks.queues import DEFAULT_QUEUE

GENERATE_REPORT_TASK = "sentinel.generate_report"
# Celery's limits sit above the in-process render timeout, which normally
# ends a slow render first with a structured FAILED result.
CELERY_SOFT_GRACE_SECONDS = 30
CELERY_HARD_GRACE_SECONDS = 60


class ReportDispatcher(Protocol):
    def send(self, report_id: uuid.UUID, render_timeout_seconds: int) -> str: ...


class CeleryReportDispatcher:
    def send(self, report_id: uuid.UUID, render_timeout_seconds: int) -> str:
        from app.core.tasks.celery_app import celery_app

        result = celery_app.send_task(
            GENERATE_REPORT_TASK,
            args=[str(report_id)],
            queue=DEFAULT_QUEUE,
            soft_time_limit=render_timeout_seconds + CELERY_SOFT_GRACE_SECONDS,
            time_limit=render_timeout_seconds + CELERY_HARD_GRACE_SECONDS,
        )
        return str(result.id)


def get_report_dispatcher() -> ReportDispatcher:
    return CeleryReportDispatcher()
