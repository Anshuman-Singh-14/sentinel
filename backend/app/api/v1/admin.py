"""Admin endpoints: users, sessions, audit trail and security alerts.

Every route requires the ``admin`` role (router-level dependency). Denials are
audited by ``require_admin`` itself.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Select, select

from app.api.v1.auth import UserOut
from app.core.audit import AuditAction, Outcome
from app.core.auth import users as user_admin
from app.core.auth.dependencies import (
    AdminDep,
    AuditDep,
    LimiterDep,
    SessionDep,
    SettingsDep,
    require_admin,
)
from app.core.auth.passwords import MAX_LENGTH
from app.core.auth.roles import Role
from app.core.errors import NotFound
from app.core.ratelimit import raise_if_limited
from app.db.models import AuditEvent, SecurityAlert, User, UserSession
from app.db.models._types import utcnow
from app.reports.csv_safe import write_csv

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])

VERIFY_LIMIT_PER_MINUTE = 6
EXPORT_LIMIT_PER_MINUTE = 6
AUDIT_PAGE_MAX = 200


# ------------------------------------------------------------------- users


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64, pattern=user_admin.USERNAME_INPUT_PATTERN)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)
    role: Role


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None


class SessionInfo(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    source_ip: str | None
    user_agent: str | None
    revoked_at: datetime | None
    revoked_reason: str | None


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserOut]:
    rows = await db.scalars(select(User).order_by(User.username).limit(limit).offset(offset))
    return [UserOut.from_model(user) for user in rows]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest, principal: AdminDep, db: SessionDep, audit: AuditDep
) -> UserOut:
    user = await user_admin.create_user(
        db,
        audit,
        actor=principal.actor,
        username=body.username,
        password=body.password,
        role=body.role,
    )
    return UserOut.from_model(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdateRequest,
    principal: AdminDep,
    db: SessionDep,
    audit: AuditDep,
) -> UserOut:
    user = await user_admin.update_user(
        db, audit, actor=principal.actor, user_id=user_id, role=body.role, is_active=body.is_active
    )
    return UserOut.from_model(user)


@router.get("/users/{user_id}/sessions", response_model=list[SessionInfo])
async def list_user_sessions(user_id: uuid.UUID, db: SessionDep) -> list[SessionInfo]:
    if await db.get(User, user_id) is None:
        raise NotFound("User not found.")
    rows = await db.scalars(
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.created_at.desc())
        .limit(50)
    )
    return [
        SessionInfo(
            id=row.id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            absolute_expires_at=row.absolute_expires_at,
            source_ip=row.source_ip,
            user_agent=row.user_agent,
            revoked_at=row.revoked_at,
            revoked_reason=row.revoked_reason,
        )
        for row in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID, principal: AdminDep, db: SessionDep, audit: AuditDep
) -> Response:
    await user_admin.revoke_session(db, audit, actor=principal.actor, session_id=session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------- audit


class AuditEventOut(BaseModel):
    id: int
    event_id: uuid.UUID
    occurred_at: datetime
    actor_type: str
    user_id: uuid.UUID | None
    username: str | None
    role: str | None
    session_id: uuid.UUID | None
    source_ip: str | None
    user_agent: str | None
    service: str
    hostname: str
    process_user: str
    action: str
    resource_type: str | None
    resource_id: str | None
    target: str | None
    outcome: str
    reason: str | None
    details: dict[str, Any]
    request_id: str | None
    is_security_event: bool
    prev_hash: str
    row_hash: str


class AuditPage(BaseModel):
    events: list[AuditEventOut]
    # Pass as ``before_id`` to fetch the next (older) page; null on the last page.
    next_before_id: int | None


class VerifyResponse(BaseModel):
    ok: bool
    checked: int
    head_hash: str
    first_broken_id: int | None
    reason: str | None


@dataclass(frozen=True)
class AuditFilters:
    """The audit viewer's filters, shared by the paged listing and the export."""

    username: str | None = None
    action: AuditAction | None = None
    outcome: Outcome | None = None
    security_only: bool = False
    since: datetime | None = None
    until: datetime | None = None

    def apply(self, query: Select[AuditEvent]) -> Select[AuditEvent]:
        if self.username:
            query = query.where(AuditEvent.username == self.username.lower())
        if self.action:
            query = query.where(AuditEvent.action == self.action.value)
        if self.outcome:
            query = query.where(AuditEvent.outcome == self.outcome.value)
        if self.security_only:
            query = query.where(AuditEvent.is_security_event.is_(True))
        if self.since:
            query = query.where(AuditEvent.occurred_at >= self.since)
        if self.until:
            query = query.where(AuditEvent.occurred_at < self.until)
        return query

    def describe(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "action": self.action.value if self.action else None,
            "outcome": self.outcome.value if self.outcome else None,
            "security_only": self.security_only,
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
        }


def audit_filters(
    username: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[AuditAction | None, Query()] = None,
    outcome: Annotated[Outcome | None, Query()] = None,
    security_only: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
) -> AuditFilters:
    return AuditFilters(username, action, outcome, security_only, since, until)


AuditFiltersDep = Annotated[AuditFilters, Depends(audit_filters)]


@router.get("/audit", response_model=AuditPage)
async def list_audit_events(
    db: SessionDep,
    filters: AuditFiltersDep,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=AUDIT_PAGE_MAX)] = 50,
) -> AuditPage:
    # Keyset pagination (newest first): stable under concurrent inserts and
    # cheap at any depth, unlike OFFSET.
    query = filters.apply(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit + 1))
    if before_id:
        query = query.where(AuditEvent.id < before_id)
    rows = list(await db.scalars(query))
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        events=[AuditEventOut.model_validate(row, from_attributes=True) for row in rows],
        next_before_id=rows[-1].id if has_more and rows else None,
    )


AUDIT_CSV_COLUMNS = (
    "id",
    "event_id",
    "occurred_at",
    "action",
    "outcome",
    "is_security_event",
    "actor_type",
    "username",
    "role",
    "user_id",
    "session_id",
    "source_ip",
    "user_agent",
    "service",
    "hostname",
    "resource_type",
    "resource_id",
    "target",
    "reason",
    "request_id",
    "details",
    "prev_hash",
    "row_hash",
)


@router.get("/audit/export", response_class=Response)
async def export_audit_events(
    principal: AdminDep,
    db: SessionDep,
    audit: AuditDep,
    limiter: LimiterDep,
    settings: SettingsDep,
    filters: AuditFiltersDep,
    export_format: Annotated[Literal["csv", "json"], Query(alias="format")] = "csv",
) -> Response:
    """The filtered audit trail as a file (03-logging-audit.md section 6).

    Newest first, capped at ``audit_export_max_rows`` (the response says when
    the cap cut the export short). Already-redacted details are exported as
    stored; CSV cells are formula-injection safe, because usernames, user
    agents and targets are attacker-influenced. The export itself is audited
    (``audit.exported``) before any data leaves, and fails closed.
    """
    raise_if_limited(
        await limiter.hit(
            f"audit-export:user:{principal.user_id}",
            limit=EXPORT_LIMIT_PER_MINUTE,
            window_seconds=60,
        )
    )
    cap = settings.audit_export_max_rows
    query = filters.apply(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(cap + 1))
    rows = list(await db.scalars(query))
    truncated = len(rows) > cap
    rows = rows[:cap]
    events = [AuditEventOut.model_validate(row, from_attributes=True) for row in rows]
    exported_at = utcnow()

    await audit.record(
        AuditAction.AUDIT_EXPORTED,
        actor=principal.actor,
        outcome=Outcome.SUCCESS,
        resource_type="audit_events",
        details={
            "format": export_format,
            "rows": len(events),
            "truncated": truncated,
            "filters": filters.describe(),
            "first_id": events[-1].id if events else None,
            "last_id": events[0].id if events else None,
        },
    )

    if export_format == "json":
        body = json.dumps(
            {
                "exported_at": exported_at.isoformat(),
                "exported_by": principal.username,
                "filters": filters.describe(),
                "row_count": len(events),
                "truncated": truncated,
                "events": [e.model_dump(mode="json") for e in events],
            },
            indent=2,
        ).encode("utf-8")
        media_type = "application/json"
    else:
        body = write_csv(
            AUDIT_CSV_COLUMNS,
            (
                [
                    json.dumps(value, sort_keys=True) if name == "details" else value
                    for name, value in ((c, getattr(e, c)) for c in AUDIT_CSV_COLUMNS)
                ]
                for e in events
            ),
        )
        media_type = "text/csv; charset=utf-8"
    filename = f"sentinel-audit-{exported_at:%Y%m%d-%H%M%S}.{export_format}"
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Export-Rows": str(len(events)),
            "X-Export-Truncated": "true" if truncated else "false",
        },
    )


@router.post("/audit/verify", response_model=VerifyResponse)
async def verify_audit_chain(
    principal: AdminDep, audit: AuditDep, limiter: LimiterDep
) -> VerifyResponse:
    # Verification reads the whole table; cap how often it can be triggered.
    raise_if_limited(
        await limiter.hit(
            f"audit-verify:user:{principal.user_id}",
            limit=VERIFY_LIMIT_PER_MINUTE,
            window_seconds=60,
        )
    )
    result = await audit.verify_chain()
    details = {
        "checked": result.checked,
        "head_hash": result.head_hash,
        "first_broken_id": result.first_broken_id,
    }
    await audit.record(
        AuditAction.AUDIT_INTEGRITY_VERIFIED if result.ok else AuditAction.AUDIT_INTEGRITY_FAILED,
        actor=principal.actor,
        outcome=Outcome.SUCCESS if result.ok else Outcome.FAILURE,
        resource_type="audit_events",
        reason=result.reason,
        details=details,
    )
    return VerifyResponse(
        ok=result.ok,
        checked=result.checked,
        head_hash=result.head_hash,
        first_broken_id=result.first_broken_id,
        reason=result.reason,
    )


# ------------------------------------------------------------------ alerts


class AlertOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    rule: str
    severity: str
    message: str
    details: dict[str, Any]
    audit_event_id: uuid.UUID | None
    acknowledged_at: datetime | None
    acknowledged_by: uuid.UUID | None


@router.get("/alerts", response_model=list[AlertOut])
async def list_alerts(
    db: SessionDep,
    unacknowledged_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[AlertOut]:
    query = select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit)
    if unacknowledged_only:
        query = query.where(SecurityAlert.acknowledged_at.is_(None))
    return [AlertOut.model_validate(row, from_attributes=True) for row in await db.scalars(query)]


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(alert_id: uuid.UUID, principal: AdminDep, db: SessionDep) -> AlertOut:
    alert = await db.get(SecurityAlert, alert_id, with_for_update=True)
    if alert is None:
        raise NotFound("Alert not found.")
    if alert.acknowledged_at is None:
        alert.acknowledged_at = utcnow()
        alert.acknowledged_by = principal.user_id
        await db.commit()
    return AlertOut.model_validate(alert, from_attributes=True)
