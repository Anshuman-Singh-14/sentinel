"""Request ID propagation from the API into Celery tasks."""

from types import SimpleNamespace
from typing import Any

import structlog

from app.core.logging.context import bind_context, clear_context
from app.core.tasks.context import (
    REQUEST_ID_HEADER,
    bind_task_context,
    clear_task_context,
    inject_request_id,
)


def _task(header: Any) -> Any:
    request = SimpleNamespace(**({REQUEST_ID_HEADER: header} if header is not None else {}))
    return SimpleNamespace(name="sentinel.ping", request=request)


def test_publish_adds_current_request_id() -> None:
    clear_context()
    bind_context(request_id="req-123")
    headers: dict[str, Any] = {}

    inject_request_id(headers=headers)

    assert headers == {REQUEST_ID_HEADER: "req-123"}


def test_publish_without_request_adds_nothing() -> None:
    clear_context()
    headers: dict[str, Any] = {}

    inject_request_id(headers=headers)

    assert headers == {}


def test_worker_restores_request_id_and_task_id() -> None:
    bind_task_context(task_id="task-1", task=_task("req-123"))

    context = structlog.contextvars.get_contextvars()
    assert context["request_id"] == "req-123"
    assert context["celery_task_id"] == "task-1"
    assert context["task_name"] == "sentinel.ping"


def test_worker_discards_malformed_request_id() -> None:
    bind_task_context(task_id="task-1", task=_task("evil\nINJECTED log line"))

    assert structlog.contextvars.get_contextvars()["request_id"] is None


def test_worker_clears_context_after_task() -> None:
    bind_task_context(task_id="task-1", task=_task("req-123"))
    clear_task_context()

    assert structlog.contextvars.get_contextvars() == {}
