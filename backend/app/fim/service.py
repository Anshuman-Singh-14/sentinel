"""Baseline management on the API side: list, schedule, delete (ADR 0015, section 8).

Baselines are created only by ``fim_baseline`` runs (in the worker). Changing
or deleting one is limited to its creator or an admin, the same rule as
cancelling a run; a refused attempt is audited.
"""

import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, AuditService, Outcome
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role, role_allows
from app.core.errors import NotFound, PermissionDenied
from app.db.models import FimBaseline, FimBaselineEntry
from app.db.models._types import utcnow

LIST_LIMIT = 200


def location(baseline: FimBaseline) -> str:
    return f"{baseline.root}:/{baseline.path}"


class FimService:
    def __init__(self, db: AsyncSession, audit: AuditService) -> None:
        self.db = db
        self.audit = audit

    async def list(self) -> list[FimBaseline]:
        rows = await self.db.scalars(
            select(FimBaseline)
            .where(FimBaseline.deleted_at.is_(None))
            .order_by(FimBaseline.id.desc())
            .limit(LIST_LIMIT)
        )
        return list(rows)

    async def _get_owned(self, baseline_id: uuid.UUID, principal: Principal) -> FimBaseline:
        baseline = await self.db.scalar(
            select(FimBaseline).where(
                FimBaseline.id == baseline_id, FimBaseline.deleted_at.is_(None)
            )
        )
        if baseline is None:
            raise NotFound("Baseline not found.")
        if baseline.created_by != principal.user_id and not role_allows(principal.role, Role.ADMIN):
            await self.audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                resource_type="fim_baseline",
                resource_id=str(baseline.id),
                reason="not_baseline_owner",
            )
            raise PermissionDenied(
                "Only the user who created a baseline, or an admin, can change it."
            )
        return baseline

    async def set_schedule(
        self, baseline_id: uuid.UUID, minutes: int | None, principal: Principal
    ) -> FimBaseline:
        baseline = await self._get_owned(baseline_id, principal)
        previous = baseline.schedule_minutes
        baseline.schedule_minutes = minutes
        # The next check is due one interval from now, not immediately.
        baseline.last_scheduled_at = utcnow() if minutes else None
        await self.audit.record(
            AuditAction.FIM_BASELINE_UPDATED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="fim_baseline",
            resource_id=str(baseline.id),
            target=location(baseline),
            details={"schedule_minutes": {"from": previous, "to": minutes}},
            session=self.db,
        )
        await self.db.commit()
        await self.db.refresh(baseline)
        return baseline

    async def delete(self, baseline_id: uuid.UUID, principal: Principal) -> None:
        """Soft delete: the row stays as a record, the entries go."""
        baseline = await self._get_owned(baseline_id, principal)
        baseline.deleted_at = utcnow()
        baseline.deleted_by = principal.user_id
        baseline.schedule_minutes = None
        await self.db.execute(
            delete(FimBaselineEntry).where(FimBaselineEntry.baseline_id == baseline.id)
        )
        await self.audit.record(
            AuditAction.FIM_BASELINE_DELETED,
            actor=principal.actor,
            outcome=Outcome.SUCCESS,
            resource_type="fim_baseline",
            resource_id=str(baseline.id),
            target=location(baseline),
            details={"name": baseline.name, "files": baseline.file_count},
            session=self.db,
        )
        await self.db.commit()
