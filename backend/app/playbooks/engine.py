"""Playbook orchestrator (worker side).

One Celery task runs a whole playbook **sequentially, in-process**: each step
becomes a normal ``ToolRun`` created through ``RunService.create`` (same role,
parameter, acknowledgement and scope checks, same audit trail) and executed
with the same ``execute_run`` a manual run uses (authoritative scope check,
persistence, progress, timeouts).

Why not a Celery chain, or sub-tasks the orchestrator waits on?
* Waiting on sub-tasks inside a task can deadlock a small worker pool, which
  Celery's own documentation warns against.
* Inline execution keeps ordering, references between steps and
  cancellation simple and deterministic. v1 is sequential by design
  (02-modules.md); parallel steps can later fan out sub-tasks.

Step outcome rules:
* A tool that is not installed, or installed but not configured (``availability()``,
  e.g. threat intel without an API key): an ``optional`` step is SKIPPED, otherwise FAILED.
* A reference that cannot be resolved, or a step the run service refuses
  (scope, validation, authorisation), means the step FAILED with that error.
* A FAILED or TIMED_OUT step with ``on_failure: stop`` stops the playbook
  (FAILED); the remaining steps are SKIPPED with the reason.
* Cancellation stops the current step cooperatively and CANCELS the rest.
"""

import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.core.audit import Actor, ActorType, AuditAction, Outcome, build_audit_service
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role
from app.core.errors import SentinelError
from app.core.logging import get_logger
from app.core.logging.context import bind_context
from app.core.ratelimit import MemoryRateLimiter
from app.core.runs import events
from app.core.runs.schemas import finding_from_row
from app.core.runs.service import RunService
from app.core.tasks.tool_task import execute_run
from app.db.models import FindingRow, PlaybookRun, ToolRun, User
from app.db.models._types import utcnow
from app.db.session import get_sessionmaker
from app.engine.base_tool import ProgressCallback
from app.engine.registry import registry
from app.playbooks.aggregate import StepFindings, merge
from app.playbooks.loader import definitions
from app.playbooks.progress import playbook_event
from app.playbooks.templating import TemplateReferenceError, render

logger = get_logger("sentinel.playbooks")

STEP_FOR_RUN_STATUS = {
    "COMPLETED": "COMPLETED",
    "FAILED": "FAILED",
    "TIMED_OUT": "TIMED_OUT",
    "CANCELLED": "CANCELLED",
}
FAILED_STEP = frozenset({"FAILED", "TIMED_OUT"})
_ACTIONS = {
    "COMPLETED": (AuditAction.PLAYBOOK_RUN_COMPLETED, Outcome.SUCCESS),
    "FAILED": (AuditAction.PLAYBOOK_RUN_FAILED, Outcome.FAILURE),
    "TIMED_OUT": (AuditAction.PLAYBOOK_RUN_FAILED, Outcome.FAILURE),
    "CANCELLED": (AuditAction.PLAYBOOK_RUN_CANCELLED, Outcome.SUCCESS),
}


def _explain(exc: SentinelError) -> str:
    """The error message plus the first field-level reason, if there is one."""
    errors = exc.details.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        loc = ".".join(str(part) for part in errors[0].get("loc", [])[1:])
        reason = str(errors[0].get("msg", "")).removeprefix("Value error, ")
        return f"{exc.message} {loc}: {reason}".strip()
    return exc.message


class _NoDispatch:
    """Playbook steps are executed inline, never sent to the queue."""

    def send(self, run_id: uuid.UUID, tool: Any) -> str:  # pragma: no cover
        raise RuntimeError("playbook steps are not dispatched")

    def revoke(self, task_id: str) -> None:  # pragma: no cover
        return None


async def _load(db: AsyncSession, playbook_run_id: uuid.UUID) -> PlaybookRun | None:
    return await db.scalar(
        select(PlaybookRun)
        .where(PlaybookRun.id == playbook_run_id)
        .options(selectinload(PlaybookRun.steps))
        .execution_options(populate_existing=True)
    )


async def _reload(db: AsyncSession, playbook_run_id: uuid.UUID) -> PlaybookRun:
    """Re-read the run after another session (or a rollback) changed it."""
    run = await _load(db, playbook_run_id)
    if run is None:  # pragma: no cover  (rows are never deleted)
        raise RuntimeError(f"playbook run {playbook_run_id} disappeared")
    return run


async def _publish(run: PlaybookRun) -> None:
    try:
        await events.publish_playbook(playbook_event(run))
    except Exception:  # noqa: BLE001  (live updates are best effort)
        logger.warning("playbook.publish_failed", playbook_run_id=str(run.id))


async def _cancel_requested(run: PlaybookRun) -> bool:
    try:
        return await events.is_playbook_cancel_requested(run.id)
    except Exception:  # noqa: BLE001  (fall back to the database flag)
        return run.cancel_requested_at is not None


def _principal(run: PlaybookRun, user: User) -> Principal:
    actor = Actor(
        actor_type=ActorType.USER,
        user_id=user.id,
        username=user.username,
        role=user.role,
        session_id=run.session_id,
    )
    return Principal(
        user_id=user.id,
        username=user.username,
        role=Role(user.role),
        session_id=run.session_id or uuid.uuid4(),
        actor=actor,
    )


async def _finish(db: AsyncSession, run: PlaybookRun, status: str, actor: Actor) -> None:
    run.status = status
    run.completed_at = utcnow()
    if run.started_at is not None:
        run.duration_ms = int((run.completed_at - run.started_at).total_seconds() * 1000)
    if status == "COMPLETED":
        run.progress_pct = 100
    run.current_step = None

    # Summary counts from the steps' findings (the detail view re-aggregates).
    step_runs = [(s.step_id, s.tool_id, s.tool_run_id) for s in run.steps if s.tool_run_id]
    collected: list[StepFindings] = []
    for step_id, tool_id, run_id in step_runs:
        rows = await db.scalars(
            select(FindingRow).where(FindingRow.run_id == run_id).order_by(FindingRow.position)
        )
        collected.append(
            StepFindings(step_id, tool_id, run_id, [finding_from_row(r) for r in rows])
        )
    merged = merge(collected)
    run.finding_count = len(merged)
    run.max_severity = merged[0].severity.value if merged else None

    action, outcome = _ACTIONS[status]
    await build_audit_service("worker").record(
        action,
        actor=actor,
        outcome=outcome,
        resource_type="playbook_run",
        resource_id=str(run.id),
        target=run.target,
        reason=(run.error or {}).get("code"),
        details={
            "playbook_id": run.playbook_id,
            "status": status,
            "steps": {s.step_id: s.status for s in run.steps},
            "finding_count": run.finding_count,
        },
        session=db,
    )
    await db.commit()
    await _publish(run)


def _progress_relay(
    run: PlaybookRun, tool_run_id: uuid.UUID, index: int, total: int
) -> ProgressCallback:
    """Turn a step's progress into overall progress (throttled) and forward cancels."""
    last_publish = 0.0

    async def relay(pct: int, message: str) -> None:
        nonlocal last_publish
        run.progress_pct = round((index + pct / 100) / total * 100)
        now = time.monotonic()
        if now - last_publish >= 0.5 or pct >= 100:
            last_publish = now
            await _publish(run)
            # A cancel request also reaches the running tool cooperatively.
            if await _cancel_requested(run):
                await events.request_cancel(tool_run_id)

    return relay


async def execute_playbook(playbook_run_id: uuid.UUID) -> str:
    registry.discover()
    settings = get_settings()
    bind_context(playbook_run_id=str(playbook_run_id))
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db:
        run = await _load(db, playbook_run_id)
        if run is None:
            logger.warning("playbook.missing")
            return "missing"
        user = await db.get(User, run.user_id)
        actor = Actor(
            actor_type=ActorType.USER,
            user_id=run.user_id,
            username=run.username,
            role=user.role if user else None,
            session_id=run.session_id,
        )
        if run.status == "RUNNING":
            # Redelivered after the previous worker died: never silently re-run.
            for step in run.steps:
                if step.status in ("PENDING", "RUNNING"):
                    step.status = "FAILED" if step.status == "RUNNING" else "SKIPPED"
                    step.error = {
                        "code": "worker_lost",
                        "message": "The worker stopped unexpectedly.",
                    }
            run.error = {"code": "worker_lost", "message": "The worker stopped unexpectedly."}
            await _finish(db, run, "FAILED", actor)
            return "FAILED"
        if run.status != "QUEUED":
            return run.status
        if run.request_id:
            # One correlation ID from the click that started it to every step.
            bind_context(request_id=run.request_id)

        run.status = "RUNNING"
        run.started_at = utcnow()
        await db.commit()
        await build_audit_service("worker").record(
            AuditAction.PLAYBOOK_RUN_STARTED,
            actor=actor,
            outcome=Outcome.SUCCESS,
            resource_type="playbook_run",
            resource_id=str(run.id),
            target=run.target,
            details={"playbook_id": run.playbook_id},
        )
        await _publish(run)

        if user is None or not user.is_active:
            run.error = {
                "code": "account_disabled",
                "message": "The requesting account is disabled.",
            }
            for step in run.steps:
                step.status = "SKIPPED"
            await _finish(db, run, "FAILED", actor)
            return "FAILED"
        principal = _principal(run, user)

        definition = definitions().get(run.playbook_id)
        specs = {s.id: s for s in definition.steps} if definition else {}
        context: dict[str, Any] = {"inputs": dict(run.inputs), "steps": {}}
        total = len(run.steps)
        final_status = "COMPLETED"

        for index, step in enumerate(run.steps):
            if await _cancel_requested(run):
                final_status = "CANCELLED"
                break
            spec = specs.get(step.step_id)
            run.current_step = step.step_id
            run.progress_pct = round(index / total * 100)
            step.started_at = utcnow()

            unusable: dict[str, str] | None = None
            if step.tool_id not in registry:
                unusable = {
                    "code": "tool_not_installed",
                    "message": f"The {step.tool_id} tool is not installed yet.",
                }
            elif not (availability := registry.get(step.tool_id).availability()).available:
                unusable = {
                    "code": "tool_unavailable",
                    "message": availability.reason or f"The {step.tool_id} tool is not available.",
                }
            if unusable is not None:
                optional = bool(spec and spec.optional)
                step.status = "SKIPPED" if optional else "FAILED"
                step.error = unusable
                step.completed_at = utcnow()
                await db.commit()
                await _publish(run)
                if not optional and step.on_failure == "stop":
                    final_status = "FAILED"
                    run.error = step.error
                    break
                continue

            try:
                params = render(spec.params if spec else {}, context)
            except TemplateReferenceError as exc:
                params = None
                step.error = {"code": "reference_error", "message": str(exc)}

            tool_run: ToolRun | None = None
            if params is not None:
                step.resolved_params = params
                service = RunService(
                    db, build_audit_service("worker"), MemoryRateLimiter(), _NoDispatch(), settings
                )
                try:
                    tool_run = await service.create(
                        registry.get(step.tool_id), params, principal, playbook_run_id=run.id
                    )
                except SentinelError as exc:
                    await db.rollback()
                    run = await _reload(db, playbook_run_id)
                    step = run.steps[index]
                    step.started_at = step.started_at or utcnow()
                    step.resolved_params = params
                    step.error = {
                        "code": exc.code,
                        "message": _explain(exc),
                        **({"details": exc.details} if exc.details else {}),
                    }

            if tool_run is None:
                step.status = "FAILED"
                step.completed_at = utcnow()
                await db.commit()
                await _publish(run)
                if step.on_failure == "stop":
                    final_status = "FAILED"
                    run.error = {
                        "code": "step_failed",
                        "message": f"Step '{step.name}' failed and is marked on_failure: stop.",
                    }
                    break
                continue

            step.tool_run_id = tool_run.id
            step.status = "RUNNING"
            await db.commit()
            await _publish(run)

            on_step_progress = _progress_relay(run, tool_run.id, index, total)
            if await _cancel_requested(run):
                await events.request_cancel(tool_run.id)
            outcome = await execute_run(tool_run.id, progress_listener=on_step_progress)

            run = await _reload(db, playbook_run_id)
            step = run.steps[index]
            finished = await db.get(ToolRun, tool_run.id, populate_existing=True)
            step.status = STEP_FOR_RUN_STATUS.get(outcome, "FAILED")
            step.completed_at = utcnow()
            if finished is not None:
                context["steps"][step.step_id] = finished.raw_data
                if finished.errors and step.status != "COMPLETED":
                    step.error = finished.errors[0]
            await db.commit()
            await _publish(run)

            if step.status == "CANCELLED":
                final_status = "CANCELLED"
                break
            if step.status in FAILED_STEP and step.on_failure == "stop":
                final_status = "FAILED"
                run.error = {
                    "code": "step_failed",
                    "message": (
                        f"Step '{step.name}' did not complete and is marked on_failure: stop."
                    ),
                }
                break

        # Whatever did not run gets an explicit status and reason.
        for step in run.steps:
            if step.status == "PENDING":
                if final_status == "CANCELLED":
                    step.status = "CANCELLED"
                else:
                    step.status = "SKIPPED"
                    step.error = {
                        "code": "stopped",
                        "message": "An earlier step stopped the playbook.",
                    }
        if final_status == "CANCELLED" and run.error is None:
            run.error = {"code": "cancelled", "message": "Cancelled by request."}
        await _finish(db, run, final_status, actor)
        logger.info("playbook.finished", status=final_status)
        return final_status


async def mark_timed_out(playbook_run_id: uuid.UUID) -> None:
    """Celery's limit interrupted the orchestrator: record it honestly."""
    async with get_sessionmaker()() as db:
        run = await _load(db, playbook_run_id)
        if run is None or run.status in ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"):
            return
        for step in run.steps:
            if step.status in ("PENDING", "RUNNING"):
                step.status = "TIMED_OUT" if step.status == "RUNNING" else "SKIPPED"
        run.error = {"code": "playbook_timeout", "message": "The playbook exceeded its time limit."}
        actor = Actor(actor_type=ActorType.USER, user_id=run.user_id, username=run.username)
        await _finish(db, run, "TIMED_OUT", actor)
