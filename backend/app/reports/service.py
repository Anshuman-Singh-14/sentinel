"""Reports on the API side: request, read, list, download.

The worker side (render, store) lives in ``app.reports.generate``.

Ordering, as for tool runs: the report row and its ``report.exported`` audit
event commit together, and only then is the task sent. Every download is
audited (``report.downloaded``) before the file leaves the server; if that
audit write fails, the download fails closed.
"""

import hashlib
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.audit import AuditAction, AuditService, Outcome
from app.core.auth.dependencies import Principal
from app.core.errors import (
    Conflict,
    IntegrityCheckFailed,
    NotFound,
    RateLimited,
    ServiceUnavailable,
    ValidationFailed,
)
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.logging.context import current_request_id
from app.core.ratelimit import RateLimiter, raise_if_limited
from app.db.models import PlaybookRun, Report, ReportBlob, ToolRun
from app.db.models._types import utcnow
from app.reports.dispatch import ReportDispatcher
from app.reports.exporters import exporters, get_exporter
from app.reports.schemas import SourceType

logger = get_logger("sentinel.reports")

ACTIVE = ("QUEUED", "RUNNING")
# A report describes a finished run; an in-flight one would be a misleading snapshot.
FINISHED = ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT")
PAGE_MAX = 100


class ReportService:
    def __init__(
        self,
        db: AsyncSession,
        audit: AuditService,
        limiter: RateLimiter,
        dispatcher: ReportDispatcher,
        settings: Settings,
    ) -> None:
        self.db = db
        self.audit = audit
        self.limiter = limiter
        self.dispatcher = dispatcher
        self.settings = settings

    # --- create ------------------------------------------------------------------------

    async def create(
        self, source_type: SourceType, source_id: uuid.UUID, fmt: str, principal: Principal
    ) -> Report:
        try:
            exporter = get_exporter(fmt)
        except LookupError:
            known = ", ".join(sorted(e.format for e in exporters()))
            raise ValidationFailed(
                f"Unknown report format. Choose one of: {known}.",
                details={
                    "errors": [
                        {"loc": ["body", "format"], "msg": "unknown format", "type": "value_error"}
                    ]
                },
            ) from None

        source: ToolRun | PlaybookRun | None
        if source_type == "tool_run":
            run = await self.db.get(ToolRun, source_id)
            source, title = run, f"{run.tool_name} report" if run else ""
        else:
            playbook = await self.db.get(PlaybookRun, source_id)
            source, title = playbook, f"{playbook.playbook_name} report" if playbook else ""
        if source is None:
            raise NotFound("The run to report on was not found.")
        if source.status not in FINISHED:
            raise Conflict("The run is still in progress. Export it once it has finished.")

        await self._enforce_quotas(principal)

        report = Report(
            id=uuid7(),
            source_type=source_type,
            source_id=source_id,
            title=title[:256],
            target=source.target,
            format=exporter.format,
            status="QUEUED",
            user_id=principal.user_id,
            username=principal.username,
            request_id=current_request_id(),
        )
        self.db.add(report)
        await self.db.flush()
        await self.audit.record(
            AuditAction.REPORT_EXPORTED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="report",
            resource_id=str(report.id),
            target=source.target,
            details={
                "source_type": source_type,
                "source_id": str(source_id),
                "format": exporter.format,
            },
            session=self.db,
        )
        await self.db.commit()

        try:
            report.celery_task_id = self.dispatcher.send(
                report.id, self.settings.report_render_timeout_seconds
            )
        except Exception:
            logger.exception("report.dispatch_failed", report_id=str(report.id))
            report.status = "FAILED"
            report.completed_at = utcnow()
            report.error = {"code": "dispatch_failed", "message": "The task queue is unavailable."}
            await self.audit.record(
                AuditAction.REPORT_GENERATED,
                actor=principal.actor,
                outcome=Outcome.FAILURE,
                resource_type="report",
                resource_id=str(report.id),
                reason="dispatch_failed",
                session=self.db,
            )
            await self.db.commit()
            raise ServiceUnavailable("The task queue is unavailable. Try again shortly.") from None
        await self.db.commit()
        logger.info("report.queued", report_id=str(report.id), format=report.format)
        return report

    async def _enforce_quotas(self, principal: Principal) -> None:
        raise_if_limited(
            await self.limiter.hit(
                f"reports:user:{principal.user_id}",
                limit=self.settings.report_rate_limit_per_minute,
                window_seconds=60,
            )
        )
        active = await self.db.scalar(
            select(func.count())
            .select_from(Report)
            .where(Report.user_id == principal.user_id, Report.status.in_(ACTIVE))
        )
        if (active or 0) >= self.settings.max_active_reports_per_user:
            raise RateLimited(
                f"You already have {active} reports being generated. Wait for one to finish.",
                headers={"Retry-After": "5"},
            )

    # --- read --------------------------------------------------------------------------

    async def get(self, report_id: uuid.UUID) -> Report:
        report = await self.db.get(Report, report_id)
        if report is None:
            raise NotFound("Report not found.")
        return report

    async def list(
        self,
        *,
        user_id: uuid.UUID | None = None,
        source_type: SourceType | None = None,
        source_id: uuid.UUID | None = None,
        before: uuid.UUID | None = None,
        limit: int = 25,
    ) -> tuple[list[Report], uuid.UUID | None]:
        limit = max(1, min(limit, PAGE_MAX))
        # UUIDv7 ids sort by creation time: keyset pagination on id alone.
        query = select(Report).order_by(Report.id.desc()).limit(limit + 1)
        if user_id:
            query = query.where(Report.user_id == user_id)
        if source_type:
            query = query.where(Report.source_type == source_type)
        if source_id:
            query = query.where(Report.source_id == source_id)
        if before:
            query = query.where(Report.id < before)
        rows = list(await self.db.scalars(query))
        has_more = len(rows) > limit
        rows = rows[:limit]
        return rows, rows[-1].id if has_more and rows else None

    # --- download ----------------------------------------------------------------------

    async def download(self, report_id: uuid.UUID, principal: Principal) -> tuple[Report, bytes]:
        report = await self.get(report_id)
        if report.status != "COMPLETED":
            raise Conflict(f"The report is not ready ({report.status}).")
        blob = await self.db.get(ReportBlob, report.id)
        content = blob.content if blob else b""
        # Re-hash on every download: a blob changed in the database after it
        # was written is refused (and flagged) rather than served.
        if blob is None or hashlib.sha256(content).hexdigest() != report.sha256:
            logger.error("report.integrity_failed", report_id=str(report.id))
            await self.audit.record(
                AuditAction.REPORT_DOWNLOADED,
                actor=principal.actor,
                outcome=Outcome.FAILURE,
                resource_type="report",
                resource_id=str(report.id),
                target=report.target,
                reason="integrity_failed",
                security_event=True,
            )
            raise IntegrityCheckFailed
        await self.audit.record(
            AuditAction.REPORT_DOWNLOADED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="report",
            resource_id=str(report.id),
            target=report.target,
            details={
                "format": report.format,
                "size_bytes": report.size_bytes,
                "sha256": report.sha256,
                "source_type": report.source_type,
                "source_id": str(report.source_id),
            },
        )
        return report, content
