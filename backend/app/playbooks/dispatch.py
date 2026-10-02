"""Hand a playbook run to the workers (only the task name is needed API-side)."""

import uuid
from typing import Protocol

from app.engine.registry import registry
from app.playbooks.schemas import PlaybookDefinition

RUN_PLAYBOOK_TASK = "sentinel.run_playbook"
PER_STEP_OVERHEAD_SECONDS = 30
SOFT_MARGIN_SECONDS = 60
HARD_MARGIN_SECONDS = 90


def time_limits(definition: PlaybookDefinition) -> tuple[int, int]:
    """The orchestrator's Celery limits: the sum of its steps' limits plus margins.

    Each step's own (shorter) limit still applies inside execute_tool, so this
    is only the backstop for a wedged orchestrator.
    """
    total = sum(
        (registry.get(s.tool_id).hard_time_limit if s.tool_id in registry else 0)
        + PER_STEP_OVERHEAD_SECONDS
        for s in definition.steps
    )
    return total + SOFT_MARGIN_SECONDS, total + HARD_MARGIN_SECONDS


class PlaybookDispatcher(Protocol):
    def send(self, playbook_run_id: uuid.UUID, definition: PlaybookDefinition) -> str: ...

    def revoke(self, task_id: str) -> None: ...


class CeleryPlaybookDispatcher:
    def send(self, playbook_run_id: uuid.UUID, definition: PlaybookDefinition) -> str:
        from app.core.tasks.celery_app import celery_app

        soft, hard = time_limits(definition)
        result = celery_app.send_task(
            RUN_PLAYBOOK_TASK,
            args=[str(playbook_run_id)],
            queue="scans",  # it runs active tools inline
            soft_time_limit=soft,
            time_limit=hard,
        )
        return str(result.id)

    def revoke(self, task_id: str) -> None:
        from app.core.tasks.celery_app import celery_app

        celery_app.control.revoke(task_id, terminate=False)


def get_playbook_dispatcher() -> PlaybookDispatcher:
    return CeleryPlaybookDispatcher()
