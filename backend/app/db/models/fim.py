"""File integrity baselines (02-modules.md, tool 6; ADR 0015).

Design notes:

* A baseline is created by a ``fim_baseline`` tool run. ``created_by`` is
  copied from that run's user, never taken from parameters.
* Deleting a baseline is a soft delete: the row stays (who watched what, and
  who stopped), its entries are removed. The app role has no DELETE grant on
  ``fim_baselines`` (migration 0007).
* ``root`` stores the root's *name* (``FIM_ROOTS``), not the server path, so
  moving a mount does not invalidate baselines and paths never reach the API.
* Entries use ``(baseline_id, path)`` as primary key: a path appears once per
  baseline, and loading a baseline is one index range scan.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow

ENTRY_KINDS = ("file", "dir", "symlink", "other")
# The only schedules offered (minutes). Kept small so a schedule cannot be
# used to flood the worker.
SCHEDULE_CHOICES = (15, 60, 360, 1440)


class FimBaseline(Base):
    __tablename__ = "fim_baselines"
    __table_args__ = (
        CheckConstraint(
            f"schedule_minutes IS NULL OR schedule_minutes IN "
            f"({', '.join(str(m) for m in SCHEDULE_CHOICES)})",
            name="schedule_valid",
        ),
        Index("ix_fim_baselines_due", "schedule_minutes", "last_scheduled_at"),
    )

    # UUIDv7: time-ordered, so `id` doubles as the newest-first sort key.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(80))
    root: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(255), default="")
    excludes: Mapped[list[str]] = mapped_column(JSONB, default=list)

    file_count: Mapped[int] = mapped_column(Integer, default=0)
    dir_count: Mapped[int] = mapped_column(Integer, default=0)
    other_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)

    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("tool_runs.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )

    schedule_minutes: Mapped[int | None] = mapped_column(Integer)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_check_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    last_check_changes: Mapped[int | None] = mapped_column(Integer)

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT")
    )


class FimBaselineEntry(Base):
    __tablename__ = "fim_baseline_entries"
    __table_args__ = (
        CheckConstraint(f"kind IN ({', '.join(repr(k) for k in ENTRY_KINDS)})", name="kind_valid"),
    )

    baseline_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("fim_baselines.id", ondelete="CASCADE"), primary_key=True
    )
    path: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    mtime_ns: Mapped[int] = mapped_column(BigInteger, default=0)
    mode: Mapped[int] = mapped_column(Integer, default=0)
    uid: Mapped[int] = mapped_column(Integer, default=0)
    gid: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64))
    link_target: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(String(32))
