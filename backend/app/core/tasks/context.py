"""Carry the correlation ID from an API request into the Celery task it starts.

On publish, the current ``request_id`` is added to the task message headers.
When a worker starts the task, the header is restored into the log context,
along with ``celery_task_id``. One ID then ties together the HTTP request, the
worker execution, their logs and (Phase 2) their audit events
(03-logging-audit.md section 2).
"""

from typing import Any

from celery import Task
from celery.signals import before_task_publish, task_postrun, task_prerun

from app.core.ids import sanitize_request_id
from app.core.logging.context import bind_context, clear_context, current_request_id

REQUEST_ID_HEADER = "sentinel_request_id"


@before_task_publish.connect
def inject_request_id(headers: dict[str, Any] | None = None, **_: Any) -> None:
    request_id = current_request_id()
    if headers is not None and request_id:
        headers[REQUEST_ID_HEADER] = request_id


@task_prerun.connect
def bind_task_context(task_id: str | None = None, task: Task | None = None, **_: Any) -> None:
    clear_context()
    # The broker is internal, but message headers are still re-validated
    # before they reach logs.
    raw = getattr(task.request, REQUEST_ID_HEADER, None) if task is not None else None
    request_id = sanitize_request_id(raw if isinstance(raw, str) else None)
    bind_context(
        request_id=request_id,
        celery_task_id=task_id,
        task_name=task.name if task is not None else None,
    )


@task_postrun.connect
def clear_task_context(**_: Any) -> None:
    clear_context()
