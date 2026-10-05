"""Run lifecycle on the API side: create, read, list, cancel.

The worker side (claim, execute, persist) lives in app.core.tasks.tool_task.

Ordering guarantees:

1. The run row and its ``tool.run.requested`` audit event commit together.
2. Only then is the task sent, so a worker never sees a run that does not
   exist. If sending fails, the run is marked FAILED and audited.
3. Status transitions are compare-and-set in SQL, so a cancel and a worker
   start racing each other resolve to exactly one outcome.
"""

import uuid
from typing import Any

from pydantic import ValidationError
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
    ValidationFailed,
)
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.logging.context import current_request_id
from app.core.ratelimit import RateLimiter, raise_if_limited
from app.core.runs import events
from app.core.runs.dispatch import Dispatcher
from app.core.security import scope_service
from app.db.models import FindingRow, PlaybookRun, ToolRun
from app.db.models._types import utcnow
from app.engine.base_tool import BaseTool
from app.engine.schemas import RunStatus, ToolError

logger = get_logger("sentinel.runs")

ACTIVE_STATUSES = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)
PAGE_MAX = 100


def param_errors(exc: ValidationError) -> list[dict[str, Any]]:
    # Same redaction rule as the global handler: never echo the input back.
    return [
        {
            "loc": ["params", *err.get("loc", ())],
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]


class RunService:
    def __init__(
        self,
        db: AsyncSession,
        audit: AuditService,
        limiter: RateLimiter,
        dispatcher: Dispatcher,
        settings: Settings,
    ) -> None:
        self.db = db
        self.audit = audit
        self.limiter = limiter
        self.dispatcher = dispatcher
        self.settings = settings

    # --- create ---------------------------------------------------------------------

    async def create(
        self,
        tool_cls: type[BaseTool[Any]],
        raw_params: dict[str, Any],
        principal: Principal,
        *,
        playbook_run_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
        upload: dict[str, Any] | None = None,
        scheduled: bool = False,
    ) -> ToolRun:
        """Validate, authorise, persist and (unless part of a playbook) dispatch a run.

        Playbook steps go through exactly the same checks (role, parameters,
        authorised-use acknowledgement, scope) and audit trail as manual
        runs. The differences: they are not rate-limited individually
        (starting the playbook was), and they are not dispatched, because the
        playbook orchestrator executes them in order itself.

        ``run_id`` and ``upload`` come from the upload route (ADR 0014): the
        file is stored under the run id *before* the run exists, so the
        worker can never start before its file is in place. ``upload`` (name
        and size, never contents) is added to the audit details.

        ``scheduled`` marks a run started by a FIM schedule (ADR 0015) on behalf
        of the baseline's creator: per-user rate quotas are skipped (the
        schedule is the rate) and the audit details say ``trigger: schedule``.
        """
        tool = tool_cls()
        if not role_allows(principal.role, tool.required_role):
            await self.audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                target=f"tool:{tool.tool_id}",
                reason="insufficient_role",
                details={"required_role": tool.required_role.value},
            )
            raise PermissionDenied

        availability = tool_cls.availability()
        if not availability.available:
            raise Conflict(availability.reason or f"The {tool.name} tool is not available.")

        try:
            params = tool.params_model.model_validate(raw_params)
        except ValidationError as exc:
            raise ValidationFailed(
                "The tool parameters are invalid.", details={"errors": param_errors(exc)}
            ) from None
        target = tool.target_of(params)

        if tool.is_active:
            # Active tools send traffic to the target: the user must have
            # accepted the authorised-use statement, and the target must be in
            # scope. The worker repeats the scope check (authoritatively)
            # right before any packet is sent.
            status = await scope_service.acknowledgement_status(
                self.db, principal.user_id, self.settings
            )
            if not status.acknowledged:
                raise AuthorizationRequired
            scope_host = tool.scope_host(params)
            if scope_host is None:
                raise ValidationFailed("This tool needs a target.")
            policy = await scope_service.load_policy(self.db, self.settings)
            decision = await scope_service.precheck(scope_host, policy)
            if decision is not None and not decision.allowed:
                await scope_service.record_denial(
                    self.audit,
                    principal.actor,
                    tool_id=tool.tool_id,
                    decision=decision,
                    stage="api",
                )
                raise ScopeDenied(decision.reason, details={"reason": decision.code})

        if playbook_run_id is None and not scheduled:
            await self._enforce_quotas(principal)

        run = ToolRun(
            id=run_id or uuid7(),
            tool_id=tool.tool_id,
            tool_name=tool.name,
            tool_version=tool.version,
            status=RunStatus.QUEUED.value,
            params=params.model_dump(mode="json"),
            target=target,
            user_id=principal.user_id,
            username=principal.username,
            request_id=current_request_id(),
            playbook_run_id=playbook_run_id,
        )
        self.db.add(run)
        await self.db.flush()
        await self.audit.record(
            AuditAction.TOOL_RUN_REQUESTED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="tool_run",
            resource_id=str(run.id),
            target=target,
            details={
                "tool_id": tool.tool_id,
                "tool_version": tool.version,
                **({"playbook_run_id": str(playbook_run_id)} if playbook_run_id else {}),
                **({"upload": upload} if upload else {}),
                **({"trigger": "schedule"} if scheduled else {}),
            },
            session=self.db,
        )
        if tool.request_audit_action is not None:
            await self.audit.record(
                tool.request_audit_action,
                actor=principal.actor,
                outcome=Outcome.SUCCESS,
                resource_type="tool_run",
                resource_id=str(run.id),
                target=target,
                details={"tool_id": tool.tool_id, **({"upload": upload} if upload else {})},
                session=self.db,
            )
        await self.db.commit()
        if playbook_run_id is not None:
            return run  # executed inline by the playbook orchestrator

        try:
            run.celery_task_id = self.dispatcher.send(run.id, tool_cls)
        except Exception:
            logger.exception("tool.run.dispatch_failed", run_id=str(run.id))
            await self._finish_without_worker(
                run,
                RunStatus.FAILED,
                principal,
                AuditAction.TOOL_RUN_FAILED,
                ToolError(code="dispatch_failed", message="The task queue is unavailable."),
            )
            raise ServiceUnavailable("The task queue is unavailable. Try again shortly.") from None
        await self.db.commit()
        logger.info("tool.run.queued", run_id=str(run.id), tool_id=tool.tool_id)
        return run

    async def _enforce_quotas(self, principal: Principal) -> None:
        raise_if_limited(
            await self.limiter.hit(
                f"runs:user:{principal.user_id}",
                limit=self.settings.run_rate_limit_per_minute,
                window_seconds=60,
            )
        )
        raise_if_limited(
            await self.limiter.hit(
                f"runs:user-hour:{principal.user_id}",
                limit=self.settings.run_rate_limit_per_hour,
                window_seconds=3600,
            )
        )
        # One cap for everything a user has in flight: manual runs plus whole
        # playbooks (a playbook's own steps are not counted twice).
        manual = await self.db.scalar(
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
                PlaybookRun.user_id == principal.user_id,
                PlaybookRun.status.in_(ACTIVE_STATUSES),
            )
        )
        active = (manual or 0) + (playbooks or 0)
        if active >= self.settings.max_active_runs_per_user:
            raise RateLimited(
                f"You already have {active} runs in progress. Wait for one to finish.",
                headers={"Retry-After": "10"},
            )

    # --- read -------------------------------------------------------------------------

    async def get(self, run_id: uuid.UUID) -> ToolRun:
        run = await self.db.scalar(
            select(ToolRun).where(ToolRun.id == run_id).options(selectinload(ToolRun.findings))
        )
        if run is None:
            raise NotFound("Run not found.")
        return run

    async def findings(self, run: ToolRun) -> list[FindingRow]:
        return list(run.findings)

    async def list(
        self,
        *,
        user_id: uuid.UUID | None = None,
        tool_id: str | None = None,
        status: RunStatus | None = None,
        before: uuid.UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[ToolRun], uuid.UUID | None]:
        limit = max(1, min(limit, PAGE_MAX))
        # UUIDv7 ids sort by creation time: keyset pagination on id alone.
        query = select(ToolRun).order_by(ToolRun.id.desc()).limit(limit + 1)
        if user_id:
            query = query.where(ToolRun.user_id == user_id)
        if tool_id:
            query = query.where(ToolRun.tool_id == tool_id)
        if status:
            query = query.where(ToolRun.status == status.value)
        if before:
            query = query.where(ToolRun.id < before)
        rows = list(await self.db.scalars(query))
        has_more = len(rows) > limit
        rows = rows[:limit]
        return rows, rows[-1].id if has_more and rows else None

    # --- cancel ------------------------------------------------------------------------

    async def cancel(self, run_id: uuid.UUID, principal: Principal) -> ToolRun:
        run = await self.get(run_id)
        if run.user_id != principal.user_id and not role_allows(principal.role, Role.ADMIN):
            await self.audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                resource_type="tool_run",
                resource_id=str(run.id),
                reason="not_run_owner",
            )
            raise PermissionDenied("Only the user who started a run, or an admin, can cancel it.")
        if run.status_enum.is_terminal:
            raise Conflict(f"The run has already finished ({run.status}).")

        now = utcnow()
        # Still queued: cancel it outright. The worker's claim (status = QUEUED)
        # then fails and it never starts.
        cancelled_queued = await self.db.execute(
            update(ToolRun)
            .where(ToolRun.id == run.id, ToolRun.status == RunStatus.QUEUED.value)
            .values(
                status=RunStatus.CANCELLED.value,
                cancel_requested_at=now,
                completed_at=now,
            )
        )
        if cancelled_queued.rowcount:  # type: ignore[attr-defined]
            await self.audit.record(
                AuditAction.TOOL_RUN_CANCELLED,
                actor=principal.actor,
                outcome=Outcome.SUCCESS,
                resource_type="tool_run",
                resource_id=str(run.id),
                target=run.target,
                details={"stage": "queued"},
                session=self.db,
            )
            await self.db.commit()
            await self._revoke_quietly(run)
            await self._publish_quietly(run.id, RunStatus.CANCELLED)
        else:
            # Running: raise the cooperative flag; the worker records the outcome.
            await self.db.execute(
                update(ToolRun)
                .where(ToolRun.id == run.id, ToolRun.cancel_requested_at.is_(None))
                .values(cancel_requested_at=now)
            )
            await self.db.commit()
            try:
                await events.request_cancel(run.id)
            except Exception:
                logger.exception("tool.run.cancel_flag_failed", run_id=str(run.id))
                raise ServiceUnavailable("Could not signal the worker. Try again.") from None
            logger.info("tool.run.cancel_requested", run_id=str(run.id))
        await self.db.refresh(run)
        return run

    # --- helpers -------------------------------------------------------------------------

    async def _finish_without_worker(
        self,
        run: ToolRun,
        status: RunStatus,
        principal: Principal,
        action: AuditAction,
        error: ToolError,
    ) -> None:
        run.status = status.value
        run.completed_at = utcnow()
        run.errors = [error.model_dump()]
        await self.audit.record(
            action,
            actor=principal.actor,
            outcome=Outcome.FAILURE,
            resource_type="tool_run",
            resource_id=str(run.id),
            target=run.target,
            reason=error.code,
            session=self.db,
        )
        await self.db.commit()

    async def _revoke_quietly(self, run: ToolRun) -> None:
        if run.celery_task_id:
            try:
                self.dispatcher.revoke(run.celery_task_id)
            except Exception:  # noqa: BLE001  (best effort: the database guard already stops the task)
                # Best effort: the database guard already stops the task.
                logger.warning("tool.run.revoke_failed", run_id=str(run.id))

    async def _publish_quietly(self, run_id: uuid.UUID, status: RunStatus) -> None:
        try:
            await events.publish(events.RunEvent.now(run_id, status.value))
        except Exception:  # noqa: BLE001  (live updates are best effort)
            logger.warning("tool.run.publish_failed", run_id=str(run_id))
