"""The Celery task that runs a tool (01-architecture.md, "Request and task flow").

The framework, not each tool, owns everything around ``run``/``translate``:

1. **Claim** the run with a compare-and-set (QUEUED -> RUNNING). A run that
   was cancelled while queued, or already claimed, is never executed twice.
   A redelivered message for a RUNNING run means the previous worker died
   (``acks_late`` + ``reject_on_worker_lost``): it is marked FAILED rather
   than silently re-run, because re-running an active scan is a new action
   someone must ask for.
2. **Audit** ``tool.run.started``, attributed to the user who requested it.
3. **Execute** via ``execute_tool`` (timeouts, error wrapping), with progress
   published to Redis and a cooperative cancel check.
4. **Persist** the ToolResult and its findings, and audit the outcome, in
   one transaction.
5. **Publish** the final state.
"""

import asyncio
import json
import time
import uuid
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import Actor, ActorType, AuditAction, Outcome, build_audit_service
from app.core.errors import ScopeDenied
from app.core.logging import get_logger
from app.core.logging.context import bind_context
from app.core.runs import events
from app.core.runs.dispatch import RUN_TOOL_TASK
from app.core.security import scope_service
from app.core.tasks.celery_app import celery_app
from app.core.tasks.loop import reset_loop, run_async
from app.db.models import FindingRow, ToolRun, User
from app.db.models._types import utcnow
from app.db.session import get_sessionmaker
from app.engine.base_tool import ProgressCallback, ToolContext
from app.engine.registry import registry
from app.engine.runner import execute_tool
from app.engine.schemas import RunStatus, ToolError, ToolResult
from app.engine.severity import highest_severity

logger = get_logger("sentinel.worker")

PROGRESS_DB_INTERVAL_SECONDS = 1.0
CANCEL_CHECK_INTERVAL_SECONDS = 0.5

_OUTCOME_ACTIONS = {
    RunStatus.COMPLETED: (AuditAction.TOOL_RUN_COMPLETED, Outcome.SUCCESS),
    RunStatus.FAILED: (AuditAction.TOOL_RUN_FAILED, Outcome.FAILURE),
    RunStatus.TIMED_OUT: (AuditAction.TOOL_RUN_FAILED, Outcome.FAILURE),
    RunStatus.CANCELLED: (AuditAction.TOOL_RUN_CANCELLED, Outcome.SUCCESS),
}

_tools_discovered = False


def _ensure_tools() -> None:
    global _tools_discovered
    if not _tools_discovered:
        registry.discover()
        _tools_discovered = True


async def _actor_for(db: AsyncSession, run: ToolRun) -> Actor:
    user = await db.get(User, run.user_id)
    return Actor(
        actor_type=ActorType.USER,
        user_id=run.user_id,
        username=run.username,
        role=user.role if user else None,
    )


def cap_raw_output(raw: dict[str, Any], limit: int) -> dict[str, Any]:
    """Bound what is stored per run (CLAUDE.md rule 7)."""
    size = len(json.dumps(raw, default=str).encode())
    if size <= limit:
        return raw
    return {
        "_truncated": True,
        "_message": f"Raw output was {size} bytes, above the {limit}-byte storage limit.",
    }


async def _finish(
    db: AsyncSession,
    run: ToolRun,
    result: ToolResult | None,
    *,
    status: RunStatus,
    errors: list[ToolError],
    actor: Actor,
    raw_limit: int,
) -> None:
    findings = result.findings if result else []
    run.status = status.value
    run.completed_at = utcnow()
    if result is not None:
        run.duration_ms = result.duration_ms
        run.target = result.target or run.target
        run.raw_data = cap_raw_output(result.raw_data, raw_limit)
    elif run.started_at is not None:
        run.duration_ms = int((run.completed_at - run.started_at).total_seconds() * 1000)
    run.errors = [e.model_dump() for e in errors]
    run.finding_count = len(findings)
    top = highest_severity(f.severity for f in findings)
    run.max_severity = top.value if top else None
    if status is RunStatus.COMPLETED:
        run.progress_pct = 100
    for position, finding in enumerate(findings):
        db.add(
            FindingRow(
                id=finding.finding_id,
                run_id=run.id,
                position=position,
                item=finding.item,
                category=finding.category,
                status=finding.status.value,
                severity=finding.severity.value,
                severity_rationale=finding.severity_rationale,
                confidence=finding.confidence.value,
                explanation=finding.explanation,
                remediation=finding.remediation,
                evidence=finding.evidence,
                references=finding.references,
                raw_data=finding.raw_data,
            )
        )
    action, outcome = _OUTCOME_ACTIONS[status]
    await build_audit_service("worker").record(
        action,
        actor=actor,
        outcome=outcome,
        resource_type="tool_run",
        resource_id=str(run.id),
        target=run.target,
        reason=errors[0].code if errors and status is not RunStatus.COMPLETED else None,
        details={
            "tool_id": run.tool_id,
            "status": status.value,
            "finding_count": run.finding_count,
            "duration_ms": run.duration_ms,
        },
        session=db,
    )
    await db.commit()


async def _publish(run: ToolRun) -> None:
    try:
        await events.publish(
            events.RunEvent.now(
                run.id,
                run.status,
                progress_pct=run.progress_pct,
                progress_message=run.progress_message,
                finding_count=run.finding_count,
                max_severity=run.max_severity,
            )
        )
    except Exception:  # noqa: BLE001  (live updates are best effort; the DB is the source of truth)
        logger.warning("tool.run.publish_failed", run_id=str(run.id))


def _scope_checker(run: ToolRun, actor: Actor, settings: Any) -> Any:
    """Scope check for hosts a tool reaches mid-run (redirects). Denials are audited."""

    async def check(host: str) -> tuple[str, ...]:
        async with get_sessionmaker()() as session:
            decision = await scope_service.evaluate_target(session, host, settings)
        if not decision.allowed:
            await scope_service.record_denial(
                build_audit_service("worker"),
                actor,
                tool_id=run.tool_id,
                decision=decision,
                stage="redirect",
                run_id=run.id,
            )
            raise ScopeDenied(decision.reason)
        return decision.addresses

    return check


async def execute_run(
    run_id: uuid.UUID, *, progress_listener: ProgressCallback | None = None
) -> str:
    """Claim, execute, persist and audit one tool run.

    ``progress_listener`` lets a caller (the playbook orchestrator) observe
    the tool's progress without touching the run's own bookkeeping.
    """
    _ensure_tools()
    from app.config import get_settings

    settings = get_settings()
    sessionmaker = get_sessionmaker()
    bind_context(run_id=str(run_id))

    async with sessionmaker() as db:
        claimed = await db.execute(
            update(ToolRun)
            .where(ToolRun.id == run_id, ToolRun.status == RunStatus.QUEUED.value)
            .values(status=RunStatus.RUNNING.value, started_at=utcnow())
            .returning(ToolRun.id)
        )
        if claimed.first() is None:
            await db.rollback()
            run = await db.get(ToolRun, run_id)
            if run is None:
                logger.warning("tool.run.missing")
                return "missing"
            if run.status == RunStatus.RUNNING.value:
                logger.error("tool.run.worker_lost")
                await _finish(
                    db,
                    run,
                    None,
                    status=RunStatus.FAILED,
                    errors=[
                        ToolError(
                            code="worker_lost",
                            message="The worker running this tool stopped unexpectedly.",
                        )
                    ],
                    actor=await _actor_for(db, run),
                    raw_limit=settings.max_raw_output_bytes,
                )
                await _publish(run)
            else:
                logger.info("tool.run.not_claimed", status=run.status)
            return run.status
        await db.commit()

        run = await db.scalar(select(ToolRun).where(ToolRun.id == run_id))
        assert run is not None  # noqa: S101  (just claimed in this session)
        bind_context(user_id=str(run.user_id), username=run.username, tool_id=run.tool_id)
        if run.request_id:
            bind_context(request_id=run.request_id)
        actor = await _actor_for(db, run)
        await build_audit_service("worker").record(
            AuditAction.TOOL_RUN_STARTED,
            actor=actor,
            outcome=Outcome.SUCCESS,
            resource_type="tool_run",
            resource_id=str(run.id),
            target=run.target,
            details={"tool_id": run.tool_id},
        )
        await _publish(run)

        last_progress_write = 0.0
        last_cancel_check = 0.0
        cancelled = False

        # Tools may report progress from concurrent coroutines; one AsyncSession
        # must never be used concurrently, so writes are serialised.
        progress_lock = asyncio.Lock()

        async def on_progress(pct: int, message: str) -> None:
            nonlocal last_progress_write
            async with progress_lock:
                run.progress_pct = pct
                run.progress_message = message[:256]
                now = time.monotonic()
                if now - last_progress_write >= PROGRESS_DB_INTERVAL_SECONDS or pct >= 100:
                    last_progress_write = now
                    await db.commit()  # flushes the two changed attributes
                await _publish(run)
            if progress_listener is not None:
                await progress_listener(pct, message)

        async def should_cancel() -> bool:
            nonlocal last_cancel_check, cancelled
            now = time.monotonic()
            if not cancelled and now - last_cancel_check >= CANCEL_CHECK_INTERVAL_SECONDS:
                last_cancel_check = now
                try:
                    cancelled = await events.is_cancel_requested(run_id)
                except Exception:  # noqa: BLE001  (a failed check must not fail the run)
                    logger.warning("tool.run.cancel_check_failed")
            return cancelled

        try:
            tool = registry.create(run.tool_id)
        except Exception:  # noqa: BLE001  (any registry failure becomes a structured FAILED result)
            await _finish(
                db,
                run,
                None,
                status=RunStatus.FAILED,
                errors=[ToolError(code="tool_not_found", message="This tool is not installed.")],
                actor=actor,
                raw_limit=settings.max_raw_output_bytes,
            )
            await _publish(run)
            return run.status

        authorized: tuple[str, ...] = ()
        scope_check = None
        if tool.is_active:
            # The authoritative scope check: here, in the worker, right before
            # any traffic, with the worker's own view of DNS (it can resolve
            # lab names the API cannot) and the policy as it is *now*.
            try:
                host = tool.scope_host(tool.params_model.model_validate(run.params)) or ""
            except ValueError:
                host = ""
            decision = await scope_service.evaluate_target(db, host, settings)
            if not decision.allowed:
                await scope_service.record_denial(
                    build_audit_service("worker"),
                    actor,
                    tool_id=run.tool_id,
                    decision=decision,
                    stage="worker",
                    run_id=run.id,
                )
                await _finish(
                    db,
                    run,
                    None,
                    status=RunStatus.FAILED,
                    errors=[ToolError(code="scope_denied", message=decision.reason)],
                    actor=actor,
                    raw_limit=settings.max_raw_output_bytes,
                )
                await _publish(run)
                return run.status
            authorized = decision.addresses
            scope_check = _scope_checker(run, actor, settings)

        ctx = ToolContext(
            run_id=run_id,
            logger=logger.bind(run_id=str(run_id), tool_id=run.tool_id),
            progress_callback=on_progress,
            cancel_check=should_cancel,
            authorized_addresses=authorized,
            scope_check=scope_check,
        )
        result = await execute_tool(
            tool, run.params, run_id=run_id, initiated_by=run.username, ctx=ctx
        )
        await _finish(
            db,
            run,
            result,
            status=result.status,
            errors=result.errors,
            actor=actor,
            raw_limit=settings.max_raw_output_bytes,
        )
        await _publish(run)
        logger.info("tool.run.finished", status=run.status, finding_count=run.finding_count)
        return run.status


async def mark_timed_out(run_id: uuid.UUID) -> None:
    """Record a run killed by Celery's soft limit (the tool ignored its own timeout)."""
    from app.config import get_settings

    async with get_sessionmaker()() as db:
        run = await db.get(ToolRun, run_id)
        if run is None or RunStatus(run.status).is_terminal:
            return
        await _finish(
            db,
            run,
            None,
            status=RunStatus.TIMED_OUT,
            errors=[ToolError(code="tool_timeout", message="The tool exceeded its time limit.")],
            actor=await _actor_for(db, run),
            raw_limit=get_settings().max_raw_output_bytes,
        )
        await _publish(run)


@celery_app.task(name=RUN_TOOL_TASK, acks_late=True)
def run_tool(run_id: str) -> str:
    """Entry point. Accepts only a run id: parameters are read from the database,
    never trusted from the message (the broker is internal, but defence in depth)."""
    parsed = uuid.UUID(run_id)
    try:
        return run_async(execute_run(parsed))
    except SoftTimeLimitExceeded:
        logger.error("tool.run.celery_soft_limit", run_id=run_id)
        reset_loop()
        run_async(mark_timed_out(parsed))
        return RunStatus.TIMED_OUT.value
