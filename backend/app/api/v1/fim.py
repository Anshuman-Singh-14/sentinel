"""FIM baseline management (Phase 11, ADR 0015).

* ``GET /fim/baselines``: any authenticated role, like runs.
* ``PATCH /fim/baselines/{id}``: set or clear the check schedule (creator or admin).
* ``DELETE /fim/baselines/{id}``: soft delete (creator or admin).

Baselines are created by running the ``fim_baseline`` tool and checked by
running ``fim_check``, through the normal run endpoints.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.core.audit import AuditService, get_audit_service
from app.core.auth.dependencies import AnalystDep, SessionDep, ViewerDep
from app.db.models.fim import SCHEDULE_CHOICES
from app.fim.schemas import BaselineList, BaselineOut, BaselineUpdate
from app.fim.service import FimService

router = APIRouter(tags=["fim"])


def get_fim_service(
    db: SessionDep, audit: Annotated[AuditService, Depends(get_audit_service)]
) -> FimService:
    return FimService(db, audit)


FimServiceDep = Annotated[FimService, Depends(get_fim_service)]


@router.get("/fim/baselines", response_model=BaselineList)
async def list_baselines(principal: ViewerDep, fim: FimServiceDep) -> BaselineList:
    return BaselineList(
        baselines=[BaselineOut.from_row(b) for b in await fim.list()],
        schedule_choices=list(SCHEDULE_CHOICES),
    )


@router.patch("/fim/baselines/{baseline_id}", response_model=BaselineOut)
async def update_baseline(
    baseline_id: uuid.UUID, body: BaselineUpdate, principal: AnalystDep, fim: FimServiceDep
) -> BaselineOut:
    return BaselineOut.from_row(
        await fim.set_schedule(baseline_id, body.schedule_minutes, principal)
    )


@router.delete("/fim/baselines/{baseline_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_baseline(
    baseline_id: uuid.UUID, principal: AnalystDep, fim: FimServiceDep
) -> Response:
    await fim.delete(baseline_id, principal)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
