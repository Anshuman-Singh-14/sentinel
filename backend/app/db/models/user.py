"""User accounts and their login sessions (03-logging-audit.md section 1).

Design notes:

* Roles are a fixed set (``Role``), so they are a constrained column rather
  than a ``roles`` table. A join table would add nothing but a join (ADR 0003).
* Sessions store only SHA-256 digests of their tokens. A database leak gives
  an attacker no usable cookie. A fast hash is fine here (unlike passwords)
  because the tokens are 256-bit random values, so brute force is hopeless.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import expression, func

from app.core.auth.roles import Role
from app.core.ids import uuid7
from app.db.base import Base
from app.db.models._types import utcnow

ROLE_VALUES = ", ".join(f"'{role.value}'" for role in Role)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(f"role IN ({ROLE_VALUES})", name="role_valid"),
        # Usernames are normalised to lower case before storage, so a plain
        # unique index is case-insensitive in effect. The check enforces it.
        CheckConstraint("username = lower(username)", name="username_lowercase"),
        CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=expression.true(), default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow, onupdate=utcnow
    )

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def role_enum(self) -> Role:
        return Role(self.role)


class UserSession(Base):
    """One login. Holds the current access, refresh and CSRF token digests.

    ``previous_refresh_token_hash`` enables refresh-token reuse detection: if
    a rotated-out refresh token is presented again, someone else holds a copy,
    so the whole session is revoked (ADR 0003).
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    access_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    previous_refresh_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64))
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    refresh_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship(back_populates="sessions")
