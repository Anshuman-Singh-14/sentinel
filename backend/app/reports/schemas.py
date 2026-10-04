"""API shapes for reports."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Report

ReportStatus = Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]
SourceType = Literal["tool_run", "playbook_run"]


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: SourceType
    source_id: uuid.UUID
    # Shape only here; the service checks it against the exporter registry.
    format: str = Field(min_length=2, max_length=8, pattern=r"^[a-z][a-z0-9]{1,7}$")


class ReportFormat(BaseModel):
    format: str
    label: str
    media_type: str
    extension: str


class ReportError(BaseModel):
    code: str
    message: str


class ReportOut(BaseModel):
    report_id: uuid.UUID
    source_type: SourceType
    source_id: uuid.UUID
    title: str
    target: str | None
    format: str
    status: ReportStatus
    requested_by: str
    user_id: uuid.UUID
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    filename: str | None
    media_type: str | None
    size_bytes: int | None
    sha256: str | None
    error: ReportError | None

    @classmethod
    def from_row(cls, row: Report) -> "ReportOut":
        return cls.model_validate(
            {
                "report_id": row.id,
                "source_type": row.source_type,
                "source_id": row.source_id,
                "title": row.title,
                "target": row.target,
                "format": row.format,
                "status": row.status,
                "requested_by": row.username,
                "user_id": row.user_id,
                "created_at": row.created_at,
                "started_at": row.started_at,
                "completed_at": row.completed_at,
                "filename": row.filename,
                "media_type": row.media_type,
                "size_bytes": row.size_bytes,
                "sha256": row.sha256,
                "error": row.error,
            }
        )


class ReportPage(BaseModel):
    reports: list[ReportOut]
    next_before: uuid.UUID | None
