"""Generated reports and their stored content (02-modules.md, "Reporting & Export").

Design notes:

* A report row is created QUEUED by the API (together with its
  ``report.exported`` audit event) before the Celery task is sent, exactly
  like a tool run, so the worker never sees a report that does not exist.
* The rendered file lives in ``report_blobs``, a separate table, so listing
  reports never drags megabytes of PDF through the connection pool.
* ``sha256`` is computed when the file is written and checked again on every
  download: a blob altered in the database is refused rather than served.
* ``username`` is a snapshot, as on runs: the report stays attributable even
  if the account is later renamed or disabled.
* No DELETE grant for the app role (migration 0006): an exported report is
  evidence of what was disclosed, and when.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow

REPORT_SOURCES = ("tool_run", "playbook_run")
REPORT_FORMATS = ("pdf", "json", "csv", "txt")
REPORT_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(f"source_type IN ({_in(REPORT_SOURCES)})", name="source_type_valid"),
        CheckConstraint(f"format IN ({_in(REPORT_FORMATS)})", name="format_valid"),
        CheckConstraint(f"status IN ({_in(REPORT_STATUSES)})", name="status_valid"),
        Index("ix_reports_user_id_created_at", "user_id", "created_at"),
        Index("ix_reports_source", "source_type", "source_id"),
    )

    # UUIDv7: time-ordered, so `id` doubles as the keyset-pagination key.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    source_type: Mapped[str] = mapped_column(String(16))
    # Not a foreign key: it points at one of two tables, chosen by source_type.
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    # Snapshot of the source's name and target, for list views.
    title: Mapped[str] = mapped_column(String(256))
    target: Mapped[str | None] = mapped_column(String(512))
    format: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    username: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    celery_task_id: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    filename: Mapped[str | None] = mapped_column(String(160))
    media_type: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    # A user-safe {code, message}; internal detail stays in the worker log.
    error: Mapped[dict[str, str] | None] = mapped_column(JSONB)


class ReportBlob(Base):
    __tablename__ = "report_blobs"

    report_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True
    )
    content: Mapped[bytes] = mapped_column(LargeBinary)
