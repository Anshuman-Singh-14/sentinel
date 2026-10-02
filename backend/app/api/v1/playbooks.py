"""Playbook endpoints.

* ``GET /playbooks``: the catalogue (steps, availability, input schema).
* ``POST /playbooks/{id}/runs``: start one (analyst and up, plus each step's own role).
* ``GET /playbook-runs``, ``GET /playbook-runs/{id}``: any authenticated role.
* ``POST /playbook-runs/{id}/cancel``: the requester or an admin.
* ``POST /playbook-runs/{id}/ws-ticket``: single-use ticket for /ws/playbooks/{id}.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.config import Settings, get_settings
from app.core.audit import AuditService, get_audit_service
from app.core.auth.dependencies import AnalystDep, SessionDep, ViewerDep
from app.core.ratelimit import RateLimiter, get_rate_limiter
from app.core.runs import events
from app.core.runs.schemas import WsTicket
from app.playbooks.dispatch import PlaybookDispatcher, get_playbook_dispatcher
from app.playbooks.loader import definitions, describe
from app.playbooks.schemas import (
    PlaybookInfo,
    PlaybookRunCreate,
    PlaybookRunDetail,
    PlaybookRunPage,
)
from app.playbooks.service import PlaybookService, summary_of

router = APIRouter(tags=["playbooks"])


def get_playbook_service(
    db: SessionDep,
    audit: Annotated[AuditService, Depends(get_audit_service)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    dispatcher: Annotated[PlaybookDispatcher, Depends(get_playbook_dispatcher)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PlaybookService:
    return PlaybookService(db, audit, limiter, dispatcher, settings)


PlaybookServiceDep = Annotated[PlaybookService, Depends(get_playbook_service)]


@router.get("/playbooks", response_model=list[PlaybookInfo])
async def list_playbooks(principal: ViewerDep) -> list[PlaybookInfo]:
    return [describe(d) for d in definitions().values()]


@router.post(
    "/playbooks/{playbook_id}/runs",
    response_model=PlaybookRunDetail,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_playbook(
    playbook_id: str, body: PlaybookRunCreate, principal: AnalystDep, service: PlaybookServiceDep
) -> PlaybookRunDetail:
    run = await service.start(playbook_id, body.inputs, principal)
    return await service.detail(run.id)


@router.get("/playbook-runs", response_model=PlaybookRunPage)
async def list_playbook_runs(
    principal: ViewerDep,
    service: PlaybookServiceDep,
    mine: bool = False,
    playbook_id: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z][a-z0-9_]*$")] = None,
    before: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PlaybookRunPage:
    rows, next_before = await service.list_runs(
        user_id=principal.user_id if mine else None,
        playbook_id=playbook_id,
        before=before,
        limit=limit,
    )
    return PlaybookRunPage(runs=[summary_of(r) for r in rows], next_before=next_before)


@router.get("/playbook-runs/{playbook_run_id}", response_model=PlaybookRunDetail)
async def get_playbook_run(
    playbook_run_id: uuid.UUID, principal: ViewerDep, service: PlaybookServiceDep
) -> PlaybookRunDetail:
    return await service.detail(playbook_run_id)


@router.post("/playbook-runs/{playbook_run_id}/cancel", response_model=PlaybookRunDetail)
async def cancel_playbook_run(
    playbook_run_id: uuid.UUID, principal: AnalystDep, service: PlaybookServiceDep
) -> PlaybookRunDetail:
    await service.cancel(playbook_run_id, principal)
    return await service.detail(playbook_run_id)


@router.post("/playbook-runs/{playbook_run_id}/ws-ticket", response_model=WsTicket)
async def playbook_ws_ticket(
    playbook_run_id: uuid.UUID,
    principal: ViewerDep,
    service: PlaybookServiceDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> WsTicket:
    await service.get_run(playbook_run_id)  # 404 for unknown runs
    ticket = await events.issue_ws_ticket(
        principal.user_id, playbook_run_id, settings.ws_ticket_ttl_seconds, kind="playbook"
    )
    return WsTicket(ticket=ticket, expires_in=settings.ws_ticket_ttl_seconds)
