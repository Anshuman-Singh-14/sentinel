"""Report endpoints (Phase 13).

* ``GET /reports/formats``: the registered exporters (drives the export buttons).
* ``POST /reports``: request a report of a finished tool or playbook run (analyst and up).
* ``GET /reports``, ``GET /reports/{id}``: any authenticated role, like runs.
* ``GET /reports/{id}/download``: the file, as an attachment. Audited.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.config import Settings, get_settings
from app.core.audit import AuditService, get_audit_service
from app.core.auth.dependencies import AnalystDep, SessionDep, ViewerDep
from app.core.ratelimit import RateLimiter, get_rate_limiter
from app.reports.dispatch import ReportDispatcher, get_report_dispatcher
from app.reports.exporters import exporters
from app.reports.schemas import (
    ReportCreate,
    ReportFormat,
    ReportOut,
    ReportPage,
    SourceType,
)
from app.reports.service import ReportService

router = APIRouter(tags=["reports"])


def get_report_service(
    db: SessionDep,
    audit: Annotated[AuditService, Depends(get_audit_service)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    dispatcher: Annotated[ReportDispatcher, Depends(get_report_dispatcher)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ReportService:
    return ReportService(db, audit, limiter, dispatcher, settings)


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]


@router.get("/reports/formats", response_model=list[ReportFormat])
async def list_formats(principal: ViewerDep) -> list[ReportFormat]:
    return [
        ReportFormat(format=e.format, label=e.label, media_type=e.media_type, extension=e.extension)
        for e in exporters()
    ]


@router.post("/reports", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def create_report(
    body: ReportCreate, principal: AnalystDep, reports: ReportServiceDep
) -> ReportOut:
    report = await reports.create(body.source_type, body.source_id, body.format, principal)
    return ReportOut.from_row(report)


@router.get("/reports", response_model=ReportPage)
async def list_reports(
    principal: ViewerDep,
    reports: ReportServiceDep,
    mine: bool = False,
    source_type: SourceType | None = None,
    source_id: uuid.UUID | None = None,
    before: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> ReportPage:
    rows, next_before = await reports.list(
        user_id=principal.user_id if mine else None,
        source_type=source_type,
        source_id=source_id,
        before=before,
        limit=limit,
    )
    return ReportPage(reports=[ReportOut.from_row(r) for r in rows], next_before=next_before)


@router.get("/reports/{report_id}", response_model=ReportOut)
async def get_report(
    report_id: uuid.UUID, principal: ViewerDep, reports: ReportServiceDep
) -> ReportOut:
    return ReportOut.from_row(await reports.get(report_id))


@router.get("/reports/{report_id}/download", response_class=Response)
async def download_report(
    report_id: uuid.UUID, principal: ViewerDep, reports: ReportServiceDep
) -> Response:
    report, content = await reports.download(report_id, principal)
    # The filename is built server-side from a strict ASCII slug (reports/naming.py),
    # so it is safe inside the quoted header value.
    return Response(
        content=content,
        media_type=report.media_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
            "Cache-Control": "no-store",
            "X-Report-SHA256": report.sha256 or "",
        },
    )
