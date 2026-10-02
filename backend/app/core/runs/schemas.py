"""API shapes for runs.

``RunDetail`` *is* the standard ``ToolResult`` (CLAUDE.md rule 6) plus the
live fields a client needs while the run is in flight (progress, the
requester's id). Nothing ad hoc: findings use the engine's ``Finding`` model.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import FindingRow, ToolRun
from app.engine.schemas import (
    Confidence,
    Finding,
    FindingStatus,
    RunStatus,
    Severity,
    ToolError,
    ToolResult,
)


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Validated against the tool's own params model in the service.
    params: dict[str, Any] = Field(default_factory=dict)


class RunSummary(BaseModel):
    """One row of the run history."""

    run_id: uuid.UUID
    tool_id: str
    tool_name: str
    target: str | None
    status: RunStatus
    initiated_by: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None
    finding_count: int
    max_severity: Severity | None

    @classmethod
    def from_row(cls, run: ToolRun) -> "RunSummary":
        return cls(
            run_id=run.id,
            tool_id=run.tool_id,
            tool_name=run.tool_name,
            target=run.target,
            status=RunStatus(run.status),
            initiated_by=run.username,
            created_at=run.created_at,
            started_at=run.started_at,
            completed_at=run.completed_at,
            duration_ms=run.duration_ms,
            finding_count=run.finding_count,
            max_severity=Severity(run.max_severity) if run.max_severity else None,
        )


class RunPage(BaseModel):
    runs: list[RunSummary]
    next_before: uuid.UUID | None


def finding_from_row(row: FindingRow) -> Finding:
    return Finding(
        finding_id=row.id,
        item=row.item,
        category=row.category,
        status=FindingStatus(row.status),
        severity=Severity(row.severity),
        severity_rationale=row.severity_rationale,
        confidence=Confidence(row.confidence),
        explanation=row.explanation,
        remediation=row.remediation,
        evidence=row.evidence,
        references=row.references,
        raw_data=row.raw_data,
    )


class RunDetail(ToolResult):
    """The standard ToolResult, plus live progress and ownership."""

    params: dict[str, Any]
    user_id: uuid.UUID
    created_at: datetime
    progress_pct: int
    progress_message: str | None
    cancel_requested: bool
    # started_at falls back to created_at for runs that never started (the
    # ToolResult schema requires a value); this says which case it is.
    was_started: bool

    @classmethod
    def from_row(cls, run: ToolRun, findings: list[FindingRow]) -> "RunDetail":
        return cls(
            run_id=run.id,
            tool_id=run.tool_id,
            tool_name=run.tool_name,
            tool_version=run.tool_version,
            target=run.target,
            initiated_by=run.username,
            status=RunStatus(run.status),
            # A queued run has not started; created_at is the closest truthful value.
            started_at=run.started_at or run.created_at,
            completed_at=run.completed_at,
            duration_ms=run.duration_ms,
            findings=[finding_from_row(row) for row in findings],
            errors=[ToolError.model_validate(e) for e in run.errors],
            raw_data=run.raw_data,
            params=run.params,
            user_id=run.user_id,
            created_at=run.created_at,
            progress_pct=run.progress_pct,
            progress_message=run.progress_message,
            cancel_requested=run.cancel_requested_at is not None,
            was_started=run.started_at is not None,
        )


class WsTicket(BaseModel):
    ticket: str
    expires_in: int
