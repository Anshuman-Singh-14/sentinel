"""How the API hands a run to the workers.

Behind a small protocol so unit tests can swap in a fake, and so the API only
needs the task *name*, never the worker's code.
"""

import uuid
from typing import Any, Protocol

from app.engine.base_tool import BaseTool

RUN_TOOL_TASK = "sentinel.run_tool"
# Extra seconds Celery waits beyond the tool's own limits. The in-process
# asyncio timeout (soft limit) normally ends the run first and records
# TIMED_OUT; Celery's limits are the backstop for a tool that ignores it.
CELERY_SOFT_GRACE_SECONDS = 10
CELERY_HARD_GRACE_SECONDS = 20


class Dispatcher(Protocol):
    def send(self, run_id: uuid.UUID, tool: type[BaseTool[Any]]) -> str: ...

    def revoke(self, task_id: str) -> None: ...


class CeleryDispatcher:
    def send(self, run_id: uuid.UUID, tool: type[BaseTool[Any]]) -> str:
        from app.core.tasks.celery_app import celery_app

        result = celery_app.send_task(
            RUN_TOOL_TASK,
            args=[str(run_id)],
            queue=tool.queue,
            soft_time_limit=tool.hard_time_limit + CELERY_SOFT_GRACE_SECONDS,
            time_limit=tool.hard_time_limit + CELERY_HARD_GRACE_SECONDS,
        )
        return str(result.id)

    def revoke(self, task_id: str) -> None:
        """Stop a task that has not started yet. Running tasks stop cooperatively."""
        from app.core.tasks.celery_app import celery_app

        celery_app.control.revoke(task_id, terminate=False)


def get_dispatcher() -> Dispatcher:
    return CeleryDispatcher()
