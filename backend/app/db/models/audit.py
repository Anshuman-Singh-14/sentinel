"""Append-only, hash-chained audit trail (03-logging-audit.md section 5).

The table is protected in three layers, all created by migration 0002:

1. Grants: ``sentinel_app`` may only ``INSERT`` and ``SELECT``.
2. Triggers: ``UPDATE``, ``DELETE`` and ``TRUNCATE`` raise an exception for
   every role, including the owner (unless the owner disables the trigger).
3. Hash chain: each row's ``row_hash`` covers its content and the previous
   row's hash, so any edit or deletion is detectable by recomputing the chain.

``user_id`` deliberately has no foreign key: audit rows must outlive the users
they describe, and must never block or cascade from changes to ``users``.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Identity,
    Index,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression

from app.db.base import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("actor_type IN ('user', 'system', 'anonymous')", name="actor_type_valid"),
        CheckConstraint("outcome IN ('SUCCESS', 'FAILURE', 'DENIED')", name="outcome_valid"),
        # Serve the alert rules ("failures for this user/IP in the last T minutes")
        # and the admin filters.
        Index("ix_audit_events_action_occurred_at", "action", "occurred_at"),
        Index("ix_audit_events_source_ip_occurred_at", "source_ip", "occurred_at"),
        Index("ix_audit_events_username_occurred_at", "username", "occurred_at"),
    )

    # GENERATED ALWAYS: callers cannot choose (or reuse) a sequence number.
    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    # Who (user context, 03-logging-audit.md section 2).
    actor_type: Mapped[str] = mapped_column(String(16))
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    username: Mapped[str | None] = mapped_column(String(64))
    role: Mapped[str | None] = mapped_column(String(16))
    session_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))

    # Where (system context).
    service: Mapped[str] = mapped_column(String(32))
    hostname: Mapped[str] = mapped_column(String(255))
    process_user: Mapped[str] = mapped_column(String(64))

    # What, to what, with what result.
    action: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    target: Mapped[str | None] = mapped_column(String(512))
    outcome: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(256))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    is_security_event: Mapped[bool] = mapped_column(
        Boolean, server_default=expression.false(), index=True
    )

    # Tamper evidence.
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64), unique=True)
