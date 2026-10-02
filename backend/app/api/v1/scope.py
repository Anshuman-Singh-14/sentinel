"""Scope policy and the authorised-use acknowledgement.

* ``GET /scope``: what active tools may target (any role), so analysts know
  before they try. The hard denylist is shown to admins only: it reveals
  internal addressing.
* ``GET/POST /scope/acknowledgement``: the statement and the caller's
  acceptance of it.
* ``/admin/scope``: admins add, enable/disable, describe and remove entries.
  Every change is a ``scope.policy.changed`` security event.
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import Settings, get_settings
from app.core.audit import AuditAction, Outcome
from app.core.audit.context import client_ip
from app.core.auth.dependencies import AdminDep, AnalystDep, AuditDep, SessionDep, ViewerDep
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.security import scope_service
from app.db.models import AuthorizationAcknowledgement, ScopeEntry

router = APIRouter(tags=["scope"])
SettingsDep = Annotated[Settings, Depends(get_settings)]


class ScopeRuleOut(BaseModel):
    id: uuid.UUID | None
    kind: Literal["cidr", "domain"]
    value: str
    description: str
    source: Literal["builtin", "admin"]
    enabled: bool
    created_at: datetime | None = None


class ScopeOut(BaseModel):
    rules: list[ScopeRuleOut]
    hard_deny: list[str] | None = None


class ScopeEntryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["cidr", "domain"]
    value: str = Field(min_length=1, max_length=253)
    description: str = Field(default="", max_length=256)


class ScopeEntryUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=256)


class AcknowledgementOut(BaseModel):
    acknowledged: bool
    version: int
    statement: str
    acknowledged_at: str | None


class AcknowledgementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement_version: int


def _rule_out(row: ScopeEntry) -> ScopeRuleOut:
    return ScopeRuleOut(
        id=row.id,
        kind=row.kind,
        value=row.value,
        description=row.description,
        source="admin",
        enabled=row.enabled,
        created_at=row.created_at,
    )


async def _scope(
    db: SessionDep, settings: Settings, *, include_disabled: bool
) -> list[ScopeRuleOut]:
    builtin = [
        ScopeRuleOut(
            id=None,
            kind="cidr",
            value=rule.value,
            description="Built-in (SCOPE_DEFAULT_ALLOW)",
            source="builtin",
            enabled=True,
        )
        for rule in scope_service.builtin_rules(settings)
    ]
    query = select(ScopeEntry).order_by(ScopeEntry.created_at)
    if not include_disabled:
        query = query.where(ScopeEntry.enabled.is_(True))
    return [*builtin, *[_rule_out(row) for row in await db.scalars(query)]]


@router.get("/scope", response_model=ScopeOut)
async def get_scope(principal: ViewerDep, db: SessionDep, settings: SettingsDep) -> ScopeOut:
    return ScopeOut(rules=await _scope(db, settings, include_disabled=False))


@router.get("/scope/acknowledgement", response_model=AcknowledgementOut)
async def get_acknowledgement(
    principal: ViewerDep, db: SessionDep, settings: SettingsDep
) -> AcknowledgementOut:
    status_ = await scope_service.acknowledgement_status(db, principal.user_id, settings)
    return AcknowledgementOut(
        acknowledged=status_.acknowledged,
        version=status_.version,
        statement=status_.statement,
        acknowledged_at=status_.acknowledged_at,
    )


@router.post("/scope/acknowledgement", response_model=AcknowledgementOut)
async def acknowledge(
    body: AcknowledgementIn,
    request: Request,
    principal: AnalystDep,
    db: SessionDep,
    audit: AuditDep,
    settings: SettingsDep,
) -> AcknowledgementOut:
    if body.statement_version != settings.authorization_statement_version:
        # The client showed an outdated text; make it reload and show the current one.
        raise Conflict("The statement has changed. Reload and read the current version.")
    existing = await scope_service.acknowledgement_status(db, principal.user_id, settings)
    if not existing.acknowledged:
        db.add(
            AuthorizationAcknowledgement(
                user_id=principal.user_id,
                statement_version=settings.authorization_statement_version,
                statement_sha256=scope_service.statement_sha256(),
                source_ip=client_ip(request),
            )
        )
        await db.flush()
        await audit.record(
            AuditAction.SCOPE_AUTHORIZATION_ACKNOWLEDGED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="authorization_statement",
            resource_id=str(settings.authorization_statement_version),
            details={"statement_sha256": scope_service.statement_sha256()},
            session=db,
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()  # a concurrent request recorded it first
    return await get_acknowledgement(principal, db, settings)


# --- admin ---------------------------------------------------------------------


@router.get("/admin/scope", response_model=ScopeOut)
async def admin_get_scope(principal: AdminDep, db: SessionDep, settings: SettingsDep) -> ScopeOut:
    return ScopeOut(
        rules=await _scope(db, settings, include_disabled=True),
        hard_deny=scope_service.hard_deny_list(settings),
    )


async def _record_change(
    audit: AuditDep, principal: AdminDep, db: SessionDep, change: str, row: ScopeEntry
) -> None:
    await audit.record(
        AuditAction.SCOPE_POLICY_CHANGED,
        actor=principal.actor,
        outcome=Outcome.SUCCESS,
        resource_type="scope_entry",
        resource_id=str(row.id),
        target=row.value,
        details={
            "change": change,
            "kind": row.kind,
            "value": row.value,
            "enabled": row.enabled,
            "description": row.description,
        },
        security_event=True,
        session=db,
    )


@router.post("/admin/scope", response_model=ScopeRuleOut, status_code=status.HTTP_201_CREATED)
async def add_scope_entry(
    body: ScopeEntryCreate,
    principal: AdminDep,
    db: SessionDep,
    audit: AuditDep,
    settings: SettingsDep,
) -> ScopeRuleOut:
    value = scope_service.normalize_entry(body.kind, body.value, settings)
    row = ScopeEntry(
        kind=body.kind,
        value=value,
        description=body.description.strip(),
        created_by=principal.user_id,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise Conflict(f"{value} is already in the scope policy.") from None
    await _record_change(audit, principal, db, "added", row)
    await db.commit()
    return _rule_out(row)


@router.patch("/admin/scope/{entry_id}", response_model=ScopeRuleOut)
async def update_scope_entry(
    entry_id: uuid.UUID,
    body: ScopeEntryUpdate,
    principal: AdminDep,
    db: SessionDep,
    audit: AuditDep,
) -> ScopeRuleOut:
    row = await db.get(ScopeEntry, entry_id, with_for_update=True)
    if row is None:
        raise NotFound("Scope entry not found.")
    if body.enabled is None and body.description is None:
        raise ValidationFailed("Nothing to change.")
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.description is not None:
        row.description = body.description.strip()
    await _record_change(audit, principal, db, "updated", row)
    await db.commit()
    return _rule_out(row)


@router.delete("/admin/scope/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope_entry(
    entry_id: uuid.UUID, principal: AdminDep, db: SessionDep, audit: AuditDep
) -> Response:
    row = await db.get(ScopeEntry, entry_id, with_for_update=True)
    if row is None:
        raise NotFound("Scope entry not found.")
    await _record_change(audit, principal, db, "removed", row)
    await db.delete(row)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
