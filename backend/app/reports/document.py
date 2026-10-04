"""The normalised report document every exporter renders.

A report can come from a single tool run or a whole playbook run. Both are
turned into one ``ReportDocument`` first, so each exporter has exactly one
input shape and the PDF, CSV, JSON and text outputs can never disagree about
what was found.

The builders are pure functions over ORM rows (unit-testable without a
database); ``load_document`` is the thin async part that reads those rows.
Findings for a playbook come from ``load_detail``, the same code the API
uses, so a report shows exactly the unified findings the run page shows.
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.runs.schemas import finding_from_row
from app.db.models import FindingRow, Report, ToolRun
from app.playbooks.aggregate import StepFindings, merge, risk_summary
from app.playbooks.schemas import AggregatedFinding, PlaybookRunDetail, RiskSummary
from app.playbooks.service import load_detail

SourceType = Literal["tool_run", "playbook_run"]
SCHEMA_VERSION = "1"


class ReportTool(BaseModel):
    tool_id: str
    name: str
    version: str


class ReportStep(BaseModel):
    position: int
    step_id: str
    name: str
    tool_id: str
    status: str
    on_failure: str
    run_id: uuid.UUID | None
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None


class RawSection(BaseModel):
    """Raw tool output for the appendix (already capped at storage time)."""

    label: str
    run_id: uuid.UUID
    data: dict[str, Any]


class ReportSubject(BaseModel):
    """What the report is about: one tool run or one playbook run."""

    kind: SourceType
    id: uuid.UUID
    name: str
    version: str
    target: str | None
    status: str
    initiated_by: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None
    parameters: dict[str, Any]


class ReportDocument(BaseModel):
    schema_version: str = SCHEMA_VERSION
    report_id: uuid.UUID
    title: str
    generated_at: datetime
    generated_by: str
    subject: ReportSubject
    tools: list[ReportTool]
    steps: list[ReportStep]
    risk: RiskSummary
    # Each finding carries its source (step id, or the tool id for a single
    # run) and any other steps that reported the same thing.
    findings: list[AggregatedFinding]
    errors: list[str]
    raw: list[RawSection]


def _error_text(error: dict[str, Any] | None) -> str | None:
    if not error:
        return None
    return str(error.get("message") or error.get("code") or "error")


def from_tool_run(
    run: ToolRun,
    findings: list[FindingRow],
    *,
    report_id: uuid.UUID,
    generated_by: str,
    generated_at: datetime,
) -> ReportDocument:
    merged = merge(
        [
            StepFindings(
                run.tool_id, run.tool_id, run.id, [finding_from_row(row) for row in findings]
            )
        ]
    )
    completed = 1 if run.status == "COMPLETED" else 0
    failed = 1 if run.status in ("FAILED", "TIMED_OUT") else 0
    return ReportDocument(
        report_id=report_id,
        title=f"{run.tool_name} report",
        generated_at=generated_at,
        generated_by=generated_by,
        subject=ReportSubject(
            kind="tool_run",
            id=run.id,
            name=run.tool_name,
            version=run.tool_version,
            target=run.target,
            status=run.status,
            initiated_by=run.username,
            created_at=run.created_at,
            started_at=run.started_at,
            completed_at=run.completed_at,
            duration_ms=run.duration_ms,
            parameters=run.params,
        ),
        tools=[ReportTool(tool_id=run.tool_id, name=run.tool_name, version=run.tool_version)],
        steps=[],
        risk=risk_summary(merged, completed_steps=completed, failed_steps=failed, unit="run"),
        findings=merged,
        errors=[str(e.get("message") or e.get("code")) for e in run.errors],
        raw=[RawSection(label=run.tool_name, run_id=run.id, data=run.raw_data)]
        if run.raw_data
        else [],
    )


def from_playbook(
    detail: PlaybookRunDetail,
    tool_runs: dict[uuid.UUID, ToolRun],
    *,
    report_id: uuid.UUID,
    generated_by: str,
    generated_at: datetime,
) -> ReportDocument:
    tools: dict[str, ReportTool] = {}
    steps: list[ReportStep] = []
    raw: list[RawSection] = []
    errors: list[str] = []
    if detail.error:
        errors.append(f"Playbook: {_error_text(detail.error)}")
    for step in detail.steps:
        run = tool_runs.get(step.run.run_id) if step.run else None
        if run is not None:
            tools.setdefault(
                run.tool_id,
                ReportTool(tool_id=run.tool_id, name=run.tool_name, version=run.tool_version),
            )
            if run.raw_data:
                raw.append(
                    RawSection(
                        label=f"{step.name} ({run.tool_name})", run_id=run.id, data=run.raw_data
                    )
                )
        message = _error_text(step.error)
        if message and step.status in ("FAILED", "TIMED_OUT"):
            errors.append(f"{step.name}: {message}")
        steps.append(
            ReportStep(
                position=step.position,
                step_id=step.step_id,
                name=step.name,
                tool_id=step.tool_id,
                status=step.status,
                on_failure=step.on_failure,
                run_id=step.run.run_id if step.run else None,
                error=message,
                started_at=step.started_at,
                completed_at=step.completed_at,
            )
        )
    return ReportDocument(
        report_id=report_id,
        title=f"{detail.playbook_name} report",
        generated_at=generated_at,
        generated_by=generated_by,
        subject=ReportSubject(
            kind="playbook_run",
            id=detail.playbook_run_id,
            name=detail.playbook_name,
            version=detail.playbook_version,
            target=detail.target,
            status=detail.status,
            initiated_by=detail.initiated_by,
            created_at=detail.created_at,
            started_at=detail.started_at,
            completed_at=detail.completed_at,
            duration_ms=detail.duration_ms,
            parameters=detail.inputs,
        ),
        tools=list(tools.values()),
        steps=steps,
        risk=detail.risk,
        findings=detail.findings,
        errors=errors,
        raw=raw,
    )


async def load_document(
    db: AsyncSession, report: Report, *, generated_at: datetime
) -> ReportDocument:
    """Read the report's source and build its document. ``NotFound`` if it is gone."""
    if report.source_type == "tool_run":
        run = await db.get(ToolRun, report.source_id)
        if run is None:
            raise NotFound("The run this report was requested for no longer exists.")
        rows = list(
            await db.scalars(
                select(FindingRow).where(FindingRow.run_id == run.id).order_by(FindingRow.position)
            )
        )
        return from_tool_run(
            run,
            rows,
            report_id=report.id,
            generated_by=report.username,
            generated_at=generated_at,
        )
    detail = await load_detail(db, report.source_id)
    run_ids = [s.run.run_id for s in detail.steps if s.run]
    tool_runs = (
        {r.id: r for r in await db.scalars(select(ToolRun).where(ToolRun.id.in_(run_ids)))}
        if run_ids
        else {}
    )
    return from_playbook(
        detail,
        tool_runs,
        report_id=report.id,
        generated_by=report.username,
        generated_at=generated_at,
    )
