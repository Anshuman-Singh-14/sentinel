"""Tool runs and their findings (01-architecture.md, "Request and task flow").

Design notes:

* A run row is created QUEUED by the API *before* the Celery task is sent,
  so the task can never start for a run that does not exist.
* Status changes are guarded in SQL (``UPDATE ... WHERE status = 'QUEUED'``),
  so the API (cancel) and the worker (start) cannot both win a race.
* ``username`` is a snapshot: the run stays attributable even if the account
  is later renamed or disabled (CLAUDE.md rule 5).
* Findings get their own table, not just a JSON blob on the run, so reports
  (Phase 13) can query them across runs.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow
from app.engine.schemas import Confidence, FindingStatus, RunStatus, Severity


def _values(enum: type) -> str:
    return ", ".join(f"'{member.value}'" for member in enum)  # type: ignore[attr-defined]


class ToolRun(Base):
    __tablename__ = "tool_runs"
    __table_args__ = (
        CheckConstraint(f"status IN ({_values(RunStatus)})", name="status_valid"),
        CheckConstraint("progress_pct BETWEEN 0 AND 100", name="progress_pct_range"),
        Index("ix_tool_runs_user_id_created_at", "user_id", "created_at"),
        Index("ix_tool_runs_tool_id_created_at", "tool_id", "created_at"),
        # Fast "how many active runs does this user have" for the quota check.
        Index(
            "ix_tool_runs_active_by_user",
            "user_id",
            postgresql_where="status IN ('QUEUED', 'RUNNING')",
        ),
    )

    # UUIDv7: time-ordered, so `id` doubles as a stable keyset-pagination key.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    tool_id: Mapped[str] = mapped_column(String(64))
    tool_name: Mapped[str] = mapped_column(String(128))
    tool_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.QUEUED.value)
    # Validated parameters. Never secrets: provider keys live in the environment.
    params: Mapped[dict[str, Any]] = mapped_column(JSONB)
    target: Mapped[str | None] = mapped_column(String(512))

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), index=False
    )
    username: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    celery_task_id: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    progress_pct: Mapped[int] = mapped_column(SmallInteger, server_default="0", default=0)
    progress_message: Mapped[str | None] = mapped_column(String(256))

    # Denormalised summary for list views; recomputed from findings on completion.
    finding_count: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    max_severity: Mapped[str | None] = mapped_column(String(16))

    errors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]", default=list)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)

    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingRow.position",
    )

    @property
    def status_enum(self) -> RunStatus:
        return RunStatus(self.status)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(f"severity IN ({_values(Severity)})", name="severity_valid"),
        CheckConstraint(f"status IN ({_values(FindingStatus)})", name="status_valid"),
        CheckConstraint(f"confidence IN ({_values(Confidence)})", name="confidence_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tool_runs.id", ondelete="CASCADE"), index=True
    )
    # Order as produced by the translator (already sorted by severity).
    position: Mapped[int] = mapped_column(Integer)
    item: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    severity_rationale: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(8))
    explanation: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)
    references: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)

    run: Mapped[ToolRun] = relationship(back_populates="findings")
