"""Celery application.

The tool-running base task arrives in Phase 5. The security-relevant settings
are set explicitly instead of relying on defaults:

* JSON-only serialization. Celery can use pickle, and unpickling a message from
  a compromised broker means arbitrary code execution (CLAUDE.md rule 1).
* Soft and hard time limits on every task (rule 7).
* ``acks_late`` with prefetch 1, so a crashed worker's task is redelivered
  rather than lost, and one worker cannot hoard queued long-running scans.
"""

from typing import Any

from celery import Celery
from celery.signals import setup_logging
from kombu import Queue

from app.config import get_settings
from app.core.logging import configure_logging
from app.core.tasks import context  # noqa: F401  (connects request-ID propagation signals)
from app.core.tasks.queues import DEFAULT_QUEUE, QUEUES

_settings = get_settings()

# Task modules are listed rather than imported here: tool_task imports this
# module, so a direct import would be circular. Workers import them at startup.
celery_app = Celery(
    "sentinel",
    include=[
        "app.core.tasks.tool_task",
        "app.core.tasks.playbook_task",
        "app.core.tasks.report_task",
        "app.core.tasks.fim_task",
    ],
)
celery_app.conf.update(
    broker_url=_settings.redis_url.get_secret_value(),
    result_backend=_settings.redis_url.get_secret_value(),
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=60,
    task_time_limit=90,
    result_expires=3600,
    task_default_queue=DEFAULT_QUEUE,
    task_queues=tuple(Queue(name) for name in QUEUES),
    broker_connection_retry_on_startup=True,
    # Our structlog pipeline owns the root logger (and its redaction step).
    worker_hijack_root_logger=False,
    timezone="UTC",
    enable_utc=True,
    # Celery beat (the `beat` service) only publishes this message; a worker
    # runs it. Each due baseline becomes a normal fim_check run (ADR 0015).
    # It expires after 55 s so a backlog of ticks (beat ran while every worker
    # was down) collapses instead of starting a burst of checks.
    beat_schedule={
        "fim-scheduled-checks": {
            "task": "sentinel.fim.dispatch_scheduled",
            "schedule": 60.0,
            "options": {"queue": DEFAULT_QUEUE, "expires": 55},
        }
    },
)


@setup_logging.connect
def _configure_worker_logging(**_: Any) -> None:
    # Connecting to this signal stops Celery from installing its own logging.
    configure_logging(get_settings(), service="worker")


@celery_app.task(name="sentinel.ping")
def ping() -> str:
    """Trivial task used to verify the broker -> worker -> result round trip."""
    return "pong"
