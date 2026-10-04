"""Report generation (worker side).

1. **Claim** the report with a compare-and-set (QUEUED -> RUNNING). A
   redelivered message for a RUNNING report means the previous worker died:
   it is marked FAILED rather than rendered twice.
2. **Build** the ``ReportDocument`` from the database (the message carries
   only the report id).
3. **Render** with the exporter in a thread, under a timeout, so a slow
   render ends as a structured FAILED result instead of a killed task.
4. **Store** the file, its size and SHA-256, and audit ``report.generated``
   in the same transaction.
"""

import asyncio
import hashlib
import uuid

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.audit import Actor, ActorType, AuditAction, Outcome, build_audit_service
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.core.logging.context import bind_context
from app.db.models import Report, ReportBlob, User
from app.db.models._types import utcnow
from app.db.session import get_sessionmaker
from app.reports.document import load_document
from app.reports.exporters import get_exporter
from app.reports.naming import report_filename

logger = get_logger("sentinel.reports")


async def _actor(db: AsyncSession, report: Report) -> Actor:
    user = await db.get(User, report.user_id)
    return Actor(
        actor_type=ActorType.USER,
        user_id=report.user_id,
        username=report.username,
        role=user.role if user else None,
    )


async def _fail(db: AsyncSession, report: Report, code: str, message: str) -> str:
    report.status = "FAILED"
    report.completed_at = utcnow()
    report.error = {"code": code, "message": message}
    await build_audit_service("worker").record(
        AuditAction.REPORT_GENERATED,
        actor=await _actor(db, report),
        outcome=Outcome.FAILURE,
        resource_type="report",
        resource_id=str(report.id),
        target=report.target,
        reason=code,
        details={"format": report.format, "source_type": report.source_type},
        session=db,
    )
    await db.commit()
    logger.warning("report.failed", code=code)
    return report.status


async def generate_report(report_id: uuid.UUID) -> str:
    settings = get_settings()
    bind_context(report_id=str(report_id))
    async with get_sessionmaker()() as db:
        claimed = await db.execute(
            update(Report)
            .where(Report.id == report_id, Report.status == "QUEUED")
            .values(status="RUNNING", started_at=utcnow())
            .returning(Report.id)
        )
        if claimed.first() is None:
            await db.rollback()
            existing = await db.get(Report, report_id)
            if existing is None:
                logger.warning("report.missing")
                return "missing"
            if existing.status == "RUNNING":
                logger.error("report.worker_lost")
                return await _fail(
                    db, existing, "worker_lost", "The worker generating this report stopped."
                )
            logger.info("report.not_claimed", status=existing.status)
            return existing.status
        await db.commit()

        report = await db.get(Report, report_id)
        assert report is not None  # noqa: S101  (just claimed in this session)
        bind_context(user_id=str(report.user_id), username=report.username)
        if report.request_id:
            bind_context(request_id=report.request_id)

        try:
            doc = await load_document(db, report, generated_at=utcnow())
            exporter = get_exporter(report.format)
            content = await asyncio.wait_for(
                asyncio.to_thread(exporter.render, doc),
                timeout=settings.report_render_timeout_seconds,
            )
        except NotFound as exc:
            return await _fail(db, report, "source_missing", exc.message)
        except TimeoutError:
            return await _fail(
                db, report, "render_timeout", "The report took too long to generate."
            )
        except Exception:
            logger.exception("report.render_failed")
            return await _fail(db, report, "render_failed", "The report could not be generated.")

        if len(content) > settings.report_max_bytes:
            return await _fail(
                db,
                report,
                "too_large",
                f"The report is larger than the {settings.report_max_bytes}-byte limit. "
                "Try the CSV or PDF format.",
            )

        digest = hashlib.sha256(content).hexdigest()
        report.status = "COMPLETED"
        report.completed_at = utcnow()
        report.size_bytes = len(content)
        report.sha256 = digest
        report.media_type = exporter.media_type
        report.filename = report_filename(
            kind=report.source_type,
            name=doc.subject.name,
            target=doc.subject.target,
            created_at=report.created_at,
            extension=exporter.extension,
        )
        db.add(ReportBlob(report_id=report.id, content=content))
        await build_audit_service("worker").record(
            AuditAction.REPORT_GENERATED,
            actor=await _actor(db, report),
            outcome=Outcome.SUCCESS,
            resource_type="report",
            resource_id=str(report.id),
            target=report.target,
            details={
                "format": report.format,
                "source_type": report.source_type,
                "source_id": str(report.source_id),
                "size_bytes": len(content),
                "sha256": digest,
                "finding_count": len(doc.findings),
            },
            session=db,
        )
        await db.commit()
        logger.info("report.generated", size_bytes=len(content), format=report.format)
        return report.status


async def mark_failed(report_id: uuid.UUID, code: str, message: str) -> None:
    """Record a report killed by Celery's soft limit."""
    async with get_sessionmaker()() as db:
        report = await db.get(Report, report_id)
        if report is None or report.status in ("COMPLETED", "FAILED"):
            return
        await _fail(db, report, code, message)
