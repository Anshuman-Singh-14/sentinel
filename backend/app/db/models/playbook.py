"""Playbook runs and their steps (02-modules.md, "Security Playbook Engine").

A playbook run is an ordered list of steps; each executed step owns a normal
``ToolRun`` (linked both ways), so every step has the same persistence, audit
trail and scope enforcement as a manual run. Aggregated findings are read
from those tool runs rather than copied, so they can never disagree.
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
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow

PLAYBOOK_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT")
STEP_STATUSES = ("PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED", "CANCELLED", "TIMED_OUT")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(PLAYBOOK_STATUSES)})", name="status_valid"),
        CheckConstraint("progress_pct BETWEEN 0 AND 100", name="progress_pct_range"),
        Index("ix_playbook_runs_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    playbook_id: Mapped[str] = mapped_column(String(64))
    playbook_name: Mapped[str] = mapped_column(String(128))
    playbook_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    inputs: Mapped[dict[str, Any]] = mapped_column(JSONB)
    target: Mapped[str | None] = mapped_column(String(512))

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    username: Mapped[str] = mapped_column(String(64))
    # The session that started it, so step audit events link back to it.
    session_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
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
    current_step: Mapped[str | None] = mapped_column(String(64))
    finding_count: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    max_severity: Mapped[str | None] = mapped_column(String(16))
    error: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    steps: Mapped[list["PlaybookStep"]] = relationship(
        back_populates="playbook_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PlaybookStep.position",
    )


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(STEP_STATUSES)})", name="status_valid"),
        CheckConstraint("on_failure IN ('stop', 'continue')", name="on_failure_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    playbook_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("playbook_runs.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    step_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    tool_id: Mapped[str] = mapped_column(String(64))
    on_failure: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("tool_runs.id", ondelete="SET NULL")
    )
    # Parameters after reference resolution: exactly what the tool received.
    resolved_params: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    playbook_run: Mapped[PlaybookRun] = relationship(back_populates="steps")
