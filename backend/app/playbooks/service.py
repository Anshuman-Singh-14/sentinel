"""Playbook runs on the API side: start, read (with aggregation), list, cancel.

Starting a playbook applies, up front, the checks every one of its steps
will face again individually: role, authorised-use acknowledgement and a
scope pre-check of the target. A run that would be refused at step two is
refused before anything is sent.
"""

import uuid
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import Settings
from app.core.audit import AuditAction, AuditService, Outcome
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role, role_allows
from app.core.errors import (
    AuthorizationRequired,
    Conflict,
    NotFound,
    PermissionDenied,
    RateLimited,
    ScopeDenied,
    ServiceUnavailable,
)
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.logging.context import current_request_id
from app.core.ratelimit import RateLimiter, raise_if_limited
from app.core.runs import events
from app.core.runs.schemas import RunSummary, finding_from_row
from app.core.runs.service import ACTIVE_STATUSES
from app.core.security import scope_service
from app.db.models import FindingRow, PlaybookRun, PlaybookStep, ToolRun
from app.db.models._types import utcnow
from app.engine.schemas import Severity
from app.playbooks.aggregate import StepFindings, merge, risk_summary
from app.playbooks.dispatch import PlaybookDispatcher
from app.playbooks.loader import describe, get_definition, required_role, validate_inputs
from app.playbooks.progress import playbook_event
from app.playbooks.schemas import (
    PlaybookRunDetail,
    PlaybookRunSummary,
    StepOut,
)

logger = get_logger("sentinel.playbooks")
ACTIVE_PLAYBOOK = ("QUEUED", "RUNNING")
TERMINAL = ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT")
PAGE_MAX = 100


def summary_of(run: PlaybookRun) -> PlaybookRunSummary:
    return PlaybookRunSummary(
        playbook_run_id=run.id,
        playbook_id=run.playbook_id,
        playbook_name=run.playbook_name,
        target=run.target,
        status=run.status,
        initiated_by=run.username,
        created_at=run.created_at,
        completed_at=run.completed_at,
        duration_ms=run.duration_ms,
        finding_count=run.finding_count,
        max_severity=Severity(run.max_severity) if run.max_severity else None,
    )


async def get_playbook_run(db: AsyncSession, playbook_run_id: uuid.UUID) -> PlaybookRun:
    run = await db.scalar(
        select(PlaybookRun)
        .where(PlaybookRun.id == playbook_run_id)
        .options(selectinload(PlaybookRun.steps))
    )
    if run is None:
        raise NotFound("Playbook run not found.")
    return run


async def load_detail(db: AsyncSession, playbook_run_id: uuid.UUID) -> PlaybookRunDetail:
    """The full playbook run: steps, linked tool runs, unified findings and risk.

    Module-level so the report worker builds exactly what the API shows.
    """
    run = await get_playbook_run(db, playbook_run_id)
    run_ids = [s.tool_run_id for s in run.steps if s.tool_run_id]
    tool_runs: dict[uuid.UUID, ToolRun] = {}
    findings: dict[uuid.UUID, list[FindingRow]] = {rid: [] for rid in run_ids}
    if run_ids:
        for loaded in await db.scalars(select(ToolRun).where(ToolRun.id.in_(run_ids))):
            tool_runs[loaded.id] = loaded
        rows = await db.scalars(
            select(FindingRow).where(FindingRow.run_id.in_(run_ids)).order_by(FindingRow.position)
        )
        for row in rows:
            findings[row.run_id].append(row)

    steps_out: list[StepOut] = []
    collected: list[StepFindings] = []
    for step in run.steps:
        tool_run = tool_runs.get(step.tool_run_id) if step.tool_run_id else None
        steps_out.append(
            StepOut(
                position=step.position,
                step_id=step.step_id,
                name=step.name,
                tool_id=step.tool_id,
                on_failure=step.on_failure,
                status=step.status,
                run=RunSummary.from_row(tool_run) if tool_run else None,
                resolved_params=step.resolved_params,
                error=step.error,
                started_at=step.started_at,
                completed_at=step.completed_at,
            )
        )
        if tool_run is not None:
            collected.append(
                StepFindings(
                    step.step_id,
                    step.tool_id,
                    tool_run.id,
                    [finding_from_row(r) for r in findings[tool_run.id]],
                )
            )
    merged = merge(collected)
    completed = sum(1 for s in run.steps if s.status == "COMPLETED")
    failed = sum(1 for s in run.steps if s.status in ("FAILED", "TIMED_OUT"))
    base: dict[str, Any] = summary_of(run).model_dump()
    return PlaybookRunDetail(
        **base,
        playbook_version=run.playbook_version,
        inputs=run.inputs,
        user_id=run.user_id,
        started_at=run.started_at,
        progress_pct=run.progress_pct,
        current_step=run.current_step,
        cancel_requested=run.cancel_requested_at is not None,
        error=run.error,
        steps=steps_out,
        risk=risk_summary(merged, completed_steps=completed, failed_steps=failed),
        findings=merged,
    )


class PlaybookService:
    def __init__(
        self,
        db: AsyncSession,
        audit: AuditService,
        limiter: RateLimiter,
        dispatcher: PlaybookDispatcher,
        settings: Settings,
    ) -> None:
        self.db = db
        self.audit = audit
        self.limiter = limiter
        self.dispatcher = dispatcher
        self.settings = settings

    async def start(
        self, playbook_id: str, raw_inputs: dict[str, str], principal: Principal
    ) -> PlaybookRun:
        definition = get_definition(playbook_id)
        info = describe(definition)
        if not info.available:
            raise Conflict(info.unavailable_reason or "This playbook is not available.")
        needed = required_role(definition)
        if not role_allows(principal.role, needed):
            await self.audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                target=f"playbook:{playbook_id}",
                reason="insufficient_role",
                details={"required_role": needed.value},
            )
            raise PermissionDenied
        inputs = validate_inputs(definition, raw_inputs)
        target = inputs.get(definition.target_input)

        if info.requires_authorization:
            status = await scope_service.acknowledgement_status(
                self.db, principal.user_id, self.settings
            )
            if not status.acknowledged:
                raise AuthorizationRequired
            if target:
                policy = await scope_service.load_policy(self.db, self.settings)
                decision = await scope_service.precheck(target, policy)
                if decision is not None and not decision.allowed:
                    await scope_service.record_denial(
                        self.audit,
                        principal.actor,
                        tool_id=f"playbook:{playbook_id}",
                        decision=decision,
                        stage="api",
                    )
                    raise ScopeDenied(decision.reason, details={"reason": decision.code})

        await self._enforce_quotas(principal)

        run = PlaybookRun(
            id=uuid7(),
            playbook_id=definition.id,
            playbook_name=definition.name,
            playbook_version=definition.version,
            status="QUEUED",
            inputs=inputs,
            target=target,
            user_id=principal.user_id,
            username=principal.username,
            session_id=principal.session_id,
            request_id=current_request_id(),
        )
        run.steps = [
            PlaybookStep(
                position=position,
                step_id=step.id,
                name=step.name,
                tool_id=step.tool_id,
                on_failure=step.on_failure,
                status="PENDING",
            )
            for position, step in enumerate(definition.steps)
        ]
        self.db.add(run)
        await self.db.flush()
        await self.audit.record(
            AuditAction.PLAYBOOK_RUN_REQUESTED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="playbook_run",
            resource_id=str(run.id),
            target=target,
            details={
                "playbook_id": definition.id,
                "version": definition.version,
                "steps": [s.id for s in definition.steps],
            },
            session=self.db,
        )
        await self.db.commit()

        try:
            run.celery_task_id = self.dispatcher.send(run.id, definition)
        except Exception:
            logger.exception("playbook.dispatch_failed", playbook_run_id=str(run.id))
            run.status = "FAILED"
            run.completed_at = utcnow()
            run.error = {"code": "dispatch_failed", "message": "The task queue is unavailable."}
            for step in run.steps:
                step.status = "SKIPPED"
            await self.audit.record(
                AuditAction.PLAYBOOK_RUN_FAILED,
                actor=principal.actor,
                outcome=Outcome.FAILURE,
                resource_type="playbook_run",
                resource_id=str(run.id),
                reason="dispatch_failed",
                session=self.db,
            )
            await self.db.commit()
            raise ServiceUnavailable("The task queue is unavailable. Try again shortly.") from None
        await self.db.commit()
        return run

    async def _enforce_quotas(self, principal: Principal) -> None:
        for key, limit, window in (
            (f"runs:user:{principal.user_id}", self.settings.run_rate_limit_per_minute, 60),
            (f"runs:user-hour:{principal.user_id}", self.settings.run_rate_limit_per_hour, 3600),
        ):
            raise_if_limited(await self.limiter.hit(key, limit=limit, window_seconds=window))
        tool_runs = await self.db.scalar(
            select(func.count())
            .select_from(ToolRun)
            .where(
                ToolRun.user_id == principal.user_id,
                ToolRun.status.in_(ACTIVE_STATUSES),
                ToolRun.playbook_run_id.is_(None),
            )
        )
        playbooks = await self.db.scalar(
            select(func.count())
            .select_from(PlaybookRun)
            .where(
                PlaybookRun.user_id == principal.user_id, PlaybookRun.status.in_(ACTIVE_PLAYBOOK)
            )
        )
        active = (tool_runs or 0) + (playbooks or 0)
        if active >= self.settings.max_active_runs_per_user:
            raise RateLimited(
                f"You already have {active} runs in progress. Wait for one to finish.",
                headers={"Retry-After": "10"},
            )

    # --- read --------------------------------------------------------------------------------

    async def get_run(self, playbook_run_id: uuid.UUID) -> PlaybookRun:
        return await get_playbook_run(self.db, playbook_run_id)

    async def detail(self, playbook_run_id: uuid.UUID) -> PlaybookRunDetail:
        return await load_detail(self.db, playbook_run_id)

    async def list_runs(
        self,
        *,
        user_id: uuid.UUID | None = None,
        playbook_id: str | None = None,
        before: uuid.UUID | None = None,
        limit: int = 25,
    ) -> tuple[list[PlaybookRun], uuid.UUID | None]:
        limit = max(1, min(limit, PAGE_MAX))
        query = select(PlaybookRun).order_by(PlaybookRun.id.desc()).limit(limit + 1)
        if user_id:
            query = query.where(PlaybookRun.user_id == user_id)
        if playbook_id:
            query = query.where(PlaybookRun.playbook_id == playbook_id)
        if before:
            query = query.where(PlaybookRun.id < before)
        rows = list(await self.db.scalars(query))
        has_more = len(rows) > limit
        rows = rows[:limit]
        return rows, rows[-1].id if has_more and rows else None

    # --- cancel ----------------------------------------------------------------------------------

    async def cancel(self, playbook_run_id: uuid.UUID, principal: Principal) -> None:
        run = await self.get_run(playbook_run_id)
        if run.user_id != principal.user_id and not role_allows(principal.role, Role.ADMIN):
            await self.audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                resource_type="playbook_run",
                resource_id=str(run.id),
                reason="not_run_owner",
            )
            raise PermissionDenied(
                "Only the user who started a playbook, or an admin, can cancel it."
            )
        if run.status in TERMINAL:
            raise Conflict(f"The playbook has already finished ({run.status}).")
        now = utcnow()
        queued = await self.db.execute(
            update(PlaybookRun)
            .where(PlaybookRun.id == run.id, PlaybookRun.status == "QUEUED")
            .values(status="CANCELLED", cancel_requested_at=now, completed_at=now)
        )
        if queued.rowcount:  # type: ignore[attr-defined]
            await self.db.execute(
                update(PlaybookStep)
                .where(PlaybookStep.playbook_run_id == run.id)
                .values(status="CANCELLED")
            )
            await self.audit.record(
                AuditAction.PLAYBOOK_RUN_CANCELLED,
                actor=principal.actor,
                outcome=Outcome.SUCCESS,
                resource_type="playbook_run",
                resource_id=str(run.id),
                details={"stage": "queued"},
                session=self.db,
            )
            await self.db.commit()
            if run.celery_task_id:
                try:
                    self.dispatcher.revoke(run.celery_task_id)
                except Exception:  # noqa: BLE001  (the status guard already stops it)
                    logger.warning("playbook.revoke_failed", playbook_run_id=str(run.id))
        else:
            await self.db.execute(
                update(PlaybookRun)
                .where(PlaybookRun.id == run.id, PlaybookRun.cancel_requested_at.is_(None))
                .values(cancel_requested_at=now)
            )
            await self.db.commit()
            try:
                await events.request_playbook_cancel(run.id)
                # Stop the step that is running now, too (cooperatively).
                for step in run.steps:
                    if step.status == "RUNNING" and step.tool_run_id:
                        await events.request_cancel(step.tool_run_id)
            except Exception:
                logger.exception("playbook.cancel_flag_failed", playbook_run_id=str(run.id))
                raise ServiceUnavailable("Could not signal the worker. Try again.") from None
        try:
            refreshed = await self.get_run(run.id)
            await self.db.refresh(refreshed)
            await events.publish_playbook(playbook_event(refreshed))
        except Exception:  # noqa: BLE001  (live updates are best effort)
            logger.warning("playbook.publish_failed", playbook_run_id=str(run.id))
