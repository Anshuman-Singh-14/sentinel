"""Generic run endpoints. One set of routes serves every tool (CLAUDE.md rule 9).

* ``POST /tools/{tool_id}/runs``: start a run (role from the tool's metadata).
* ``POST /tools/{tool_id}/runs/upload``: start a run on an uploaded file, for
  tools with ``accepts_upload`` (ADR 0014). The body is the raw file.
* ``GET /runs``, ``GET /runs/{id}``: any authenticated role (viewers read results).
* ``POST /runs/{id}/cancel``: the requester or an admin.
* ``POST /runs/{id}/ws-ticket``: a single-use ticket for the live WebSocket.
"""

import json
import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.core import uploads
from app.core.audit import AuditService, get_audit_service
from app.core.auth.dependencies import (
    AnalystDep,
    SessionDep,
    ViewerDep,
)
from app.core.errors import NotFound, PayloadTooLarge, ValidationFailed
from app.core.ids import uuid7
from app.core.ratelimit import RateLimiter, get_rate_limiter
from app.core.runs import events
from app.core.runs.dispatch import Dispatcher, get_dispatcher
from app.core.runs.schemas import RunCreateRequest, RunDetail, RunPage, RunSummary, WsTicket
from app.core.runs.service import RunService, param_errors
from app.engine.registry import registry
from app.engine.schemas import RunStatus

router = APIRouter(tags=["runs"])


def get_run_service(
    db: SessionDep,
    audit: Annotated[AuditService, Depends(get_audit_service)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    dispatcher: Annotated[Dispatcher, Depends(get_dispatcher)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RunService:
    return RunService(db, audit, limiter, dispatcher, settings)


RunServiceDep = Annotated[RunService, Depends(get_run_service)]


@router.post(
    "/tools/{tool_id}/runs", response_model=RunDetail, status_code=status.HTTP_202_ACCEPTED
)
async def create_run(
    tool_id: str, body: RunCreateRequest, principal: AnalystDep, runs: RunServiceDep
) -> RunDetail:
    # AnalystDep is the floor (viewers never run tools); the service also
    # enforces the tool's own required_role, which may be higher.
    run = await runs.create(registry.get(tool_id), body.params, principal)
    return RunDetail.from_row(run, [])


_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._ -]")
MAX_PARAMS_JSON = 4096


def display_name(filename: str) -> str:
    """The uploaded file's name, for display and audit only.

    It never becomes part of a filesystem path (the stored file is named after
    the run id), but it is shown in the UI, reports and the audit log, so
    directory parts, control characters and anything unusual are removed.
    """
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _UNSAFE_NAME_CHARS.sub("_", base).strip(" .")[:255]
    return cleaned or "upload"


@router.post(
    "/tools/{tool_id}/runs/upload",
    response_model=RunDetail,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_upload_run(
    tool_id: str,
    request: Request,
    principal: AnalystDep,
    runs: RunServiceDep,
    settings: Annotated[Settings, Depends(get_settings)],
    filename: Annotated[str, Query(min_length=1, max_length=255)],
    params: Annotated[str, Query(max_length=MAX_PARAMS_JSON)] = "{}",
) -> RunDetail:
    """Stream the request body to storage, then create the run that will read it.

    Cheap checks run before a single body byte is read: the tool accepts
    uploads, the declared size fits, and the parameters are valid.
    """
    tool_cls = registry.get(tool_id)
    if not tool_cls.accepts_upload:
        raise NotFound("This tool does not accept uploads.")
    max_bytes = tool_cls.max_upload_bytes()
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise PayloadTooLarge(f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit.")
    try:
        raw_params: Any = json.loads(params)
    except ValueError:
        raise ValidationFailed("params must be a JSON object.") from None
    if not isinstance(raw_params, dict):
        raise ValidationFailed("params must be a JSON object.")
    name = display_name(filename)
    raw_params["upload_name"] = name
    try:
        tool_cls.params_model.model_validate(raw_params)
    except ValidationError as exc:
        # Same field-level 422 shape as the JSON route, before any upload.
        raise ValidationFailed(
            "The tool parameters are invalid.", details={"errors": param_errors(exc)}
        ) from None

    uploads.sweep_stale(settings.upload_dir)
    run_id = uuid7()
    size = await uploads.store(
        settings.upload_dir,
        run_id,
        request.stream(),
        max_bytes=max_bytes,
        timeout_seconds=settings.upload_timeout_seconds,
    )
    try:
        run = await runs.create(
            tool_cls,
            raw_params,
            principal,
            run_id=run_id,
            upload={"name": name, "bytes": size},
        )
    except BaseException:
        uploads.discard(settings.upload_dir, run_id)
        raise
    return RunDetail.from_row(run, [])


@router.get("/runs", response_model=RunPage)
async def list_runs(
    principal: ViewerDep,
    runs: RunServiceDep,
    mine: bool = False,
    tool_id: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z][a-z0-9_]*$")] = None,
    run_status: Annotated[RunStatus | None, Query(alias="status")] = None,
    before: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RunPage:
    rows, next_before = await runs.list(
        user_id=principal.user_id if mine else None,
        tool_id=tool_id,
        status=run_status,
        before=before,
        limit=limit,
    )
    return RunPage(runs=[RunSummary.from_row(r) for r in rows], next_before=next_before)


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(run_id: uuid.UUID, principal: ViewerDep, runs: RunServiceDep) -> RunDetail:
    run = await runs.get(run_id)
    return RunDetail.from_row(run, await runs.findings(run))


@router.post("/runs/{run_id}/cancel", response_model=RunDetail)
async def cancel_run(run_id: uuid.UUID, principal: AnalystDep, runs: RunServiceDep) -> RunDetail:
    run = await runs.cancel(run_id, principal)
    return RunDetail.from_row(run, await runs.findings(run))


@router.post("/runs/{run_id}/ws-ticket", response_model=WsTicket)
async def ws_ticket(
    run_id: uuid.UUID,
    principal: ViewerDep,
    runs: RunServiceDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> WsTicket:
    # A POST, so it carries the CSRF check; the ticket then authenticates the
    # WebSocket handshake, which cannot send custom headers.
    await runs.get(run_id)  # 404 for unknown runs
    ticket = await events.issue_ws_ticket(principal.user_id, run_id, settings.ws_ticket_ttl_seconds)
    return WsTicket(ticket=ticket, expires_in=settings.ws_ticket_ttl_seconds)
