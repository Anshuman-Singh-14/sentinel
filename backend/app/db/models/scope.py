"""Scope policy entries and authorization acknowledgements (04-security.md section 2).

Built-in entries (loopback, the lab network) come from settings and are not
stored here; this table holds what admins add. The hard infrastructure
denylist is never stored in the database, so no database write can lift it.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression, func

from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow


class ScopeEntry(Base):
    __tablename__ = "scope_entries"
    __table_args__ = (
        CheckConstraint("kind IN ('cidr', 'domain')", name="kind_valid"),
        UniqueConstraint("kind", "value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    kind: Mapped[str] = mapped_column(String(8))
    # Normalised: CIDRs in canonical form (10.0.0.0/24), domains lower-case.
    value: Mapped[str] = mapped_column(String(253))
    description: Mapped[str] = mapped_column(String(256), server_default="", default="")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=expression.true(), default=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow, onupdate=utcnow
    )


class AuthorizationAcknowledgement(Base):
    """A user's acceptance of the authorised-use statement, per statement version.

    Append-only in practice (the app role gets INSERT/SELECT only): it is
    evidence that the user accepted responsibility before scanning.
    """

    __tablename__ = "authorization_acknowledgements"
    __table_args__ = (UniqueConstraint("user_id", "statement_version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    statement_version: Mapped[int] = mapped_column(Integer)
    # SHA-256 of the exact text accepted, so a later wording change is provable.
    statement_sha256: Mapped[str] = mapped_column(String(64))
    acknowledged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )
    source_ip: Mapped[str | None] = mapped_column(String(64))
