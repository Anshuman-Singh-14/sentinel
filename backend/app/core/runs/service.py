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
from app.db.models import FindingRow, ToolRun
from app.db.models._types import utcnow
from app.engine.base_tool import BaseTool
from app.engine.schemas import RunStatus, ToolError

logger = get_logger("sentinel.runs")

ACTIVE_STATUSES = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)
PAGE_MAX = 100


def _param_errors(exc: ValidationError) -> list[dict[str, Any]]:
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
        self, tool_cls: type[BaseTool[Any]], raw_params: dict[str, Any], principal: Principal
    ) -> ToolRun:
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

        try:
            params = tool.params_model.model_validate(raw_params)
        except ValidationError as exc:
            raise ValidationFailed(
                "The tool parameters are invalid.", details={"errors": _param_errors(exc)}
            ) from None
        target = tool.target_of(params)

        if tool.is_active:
            # Fail closed: active tools send traffic to third parties, and the
            # scope policy that authorises targets arrives in Phase 6. Until
            # then no active tool may run at all.
            await self.audit.record(
                AuditAction.TOOL_RUN_DENIED_SCOPE,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                resource_type="tool",
                resource_id=tool.tool_id,
                target=target,
                reason="no_scope_policy",
                security_event=True,
            )
            raise ScopeDenied("Active tools are disabled until a scope policy is configured.")

        raise_if_limited(
            await self.limiter.hit(
                f"runs:user:{principal.user_id}",
                limit=self.settings.run_rate_limit_per_minute,
                window_seconds=60,
            )
        )
        active = await self.db.scalar(
            select(func.count())
            .select_from(ToolRun)
            .where(ToolRun.user_id == principal.user_id, ToolRun.status.in_(ACTIVE_STATUSES))
        )
        if (active or 0) >= self.settings.max_active_runs_per_user:
            raise RateLimited(
                f"You already have {active} runs in progress. Wait for one to finish.",
                headers={"Retry-After": "10"},
            )

        run = ToolRun(
            id=uuid7(),
            tool_id=tool.tool_id,
            tool_name=tool.name,
            tool_version=tool.version,
            status=RunStatus.QUEUED.value,
            params=params.model_dump(mode="json"),
            target=target,
            user_id=principal.user_id,
            username=principal.username,
            request_id=current_request_id(),
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
            details={"tool_id": tool.tool_id, "tool_version": tool.version},
            session=self.db,
        )
        await self.db.commit()

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
