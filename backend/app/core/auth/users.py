"""User administration: create, change role, enable/disable, revoke sessions.

Every change is audited in the same transaction as the change itself. Two
guard rails stop an admin from locking everyone out:

* An admin cannot change their own role or disable their own account.
* The last active admin cannot be demoted or disabled.
"""

import re
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import Actor, AuditAction, AuditService, Outcome
from app.core.auth.passwords import enforce_password_policy, hash_password
from app.core.auth.roles import Role
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.ids import uuid7
from app.db.models import User, UserSession
from app.db.models._types import utcnow

# Lower-case letters, digits and . _ - ; 3-64 characters, starting with a
# letter or digit. Restrictive on purpose: usernames appear in logs, audit
# rows and UI, so no spaces, control characters or look-alike Unicode.
USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
# Accepted at the API boundary; normalised to lower case before storage.
USERNAME_INPUT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$"
_USERNAME_RE = re.compile(USERNAME_PATTERN)


def normalize_username(username: str) -> str:
    normalized = username.strip().lower()
    if not _USERNAME_RE.fullmatch(normalized):
        raise ValidationFailed("Usernames are 3-64 characters: letters, digits, '.', '_' or '-'.")
    return normalized


async def create_user(
    db: AsyncSession,
    audit: AuditService,
    *,
    actor: Actor,
    username: str,
    password: str,
    role: Role,
) -> User:
    normalized = normalize_username(username)
    enforce_password_policy(password, username=normalized)
    if await db.scalar(select(User.id).where(User.username == normalized)) is not None:
        raise Conflict("A user with that username already exists.")
    user = User(
        id=uuid7(),
        username=normalized,
        password_hash=await hash_password(password),
        role=str(role),
        password_changed_at=utcnow(),
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:  # lost a race with a concurrent create
        await db.rollback()
        raise Conflict("A user with that username already exists.") from exc
    await audit.record(
        AuditAction.USER_CREATED,
        actor=actor,
        outcome=Outcome.SUCCESS,
        resource_type="user",
        resource_id=str(user.id),
        target=normalized,
        details={"role": str(role)},
        session=db,
    )
    await db.commit()
    return user


async def _other_active_admins(db: AsyncSession, exclude: uuid.UUID) -> int:
    count = await db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == Role.ADMIN.value, User.is_active.is_(True), User.id != exclude)
    )
    return int(count or 0)


async def _revoke_all_sessions(db: AsyncSession, user_id: uuid.UUID, reason: str) -> int:
    result = await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]


async def update_user(
    db: AsyncSession,
    audit: AuditService,
    *,
    actor: Actor,
    user_id: uuid.UUID,
    role: Role | None = None,
    is_active: bool | None = None,
) -> User:
    user = await db.scalar(select(User).where(User.id == user_id).with_for_update())
    if user is None:
        raise NotFound("User not found.")
    role_changes = role is not None and role.value != user.role
    disabling = is_active is False and user.is_active
    enabling = is_active is True and not user.is_active

    if user.id == actor.user_id and (role_changes or disabling):
        raise Conflict("You cannot change your own role or disable your own account.")
    removes_admin = user.role == Role.ADMIN.value and user.is_active and (role_changes or disabling)
    if removes_admin and await _other_active_admins(db, user.id) == 0:
        raise Conflict("At least one active admin must remain.")

    if role_changes and role is not None:
        previous = user.role
        user.role = role.value
        await audit.record(
            AuditAction.USER_ROLE_CHANGED,
            outcome=Outcome.SUCCESS,
            target=user.username,
            details={"from": previous, "to": role.value},
            session=db,
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
        )
    if disabling:
        user.is_active = False
        revoked = await _revoke_all_sessions(db, user.id, "user_disabled")
        await audit.record(
            AuditAction.USER_DISABLED,
            outcome=Outcome.SUCCESS,
            target=user.username,
            details={"revoked_count": revoked},
            session=db,
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
        )
    if enabling:
        user.is_active = True
        user.failed_login_count = 0
        user.locked_until = None
        await audit.record(
            AuditAction.USER_ENABLED,
            outcome=Outcome.SUCCESS,
            target=user.username,
            session=db,
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
        )
    await db.commit()
    return user


async def revoke_session(
    db: AsyncSession, audit: AuditService, *, actor: Actor, session_id: uuid.UUID
) -> None:
    session = await db.scalar(
        select(UserSession).where(UserSession.id == session_id).with_for_update()
    )
    if session is None:
        raise NotFound("Session not found.")
    if session.revoked_at is not None:
        return  # idempotent: already revoked, nothing to record
    owner = await db.get(User, session.user_id)
    session.revoked_at = utcnow()
    session.revoked_reason = "admin_revoked"
    await audit.record(
        AuditAction.AUTH_SESSION_REVOKED,
        actor=actor,
        outcome=Outcome.SUCCESS,
        resource_type="session",
        resource_id=str(session.id),
        target=owner.username if owner else None,
        reason="admin_revoked",
        session=db,
    )
    await db.commit()
