"""Authentication endpoints. Thin: validation here, logic in ``AuthService``."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.audit import AuditAction, Outcome
from app.core.audit.context import anonymous_actor
from app.core.auth.cookies import (
    clear_session_cookies,
    cookie_names,
    set_session_cookies,
)
from app.core.auth.csrf import csrf_failure_reason
from app.core.auth.dependencies import (
    AuditDep,
    AuthServiceDep,
    PrincipalDep,
    SettingsDep,
    require_allowed_origin,
)
from app.core.auth.passwords import MAX_LENGTH
from app.core.auth.service import IssuedSession, user_actor
from app.core.errors import CsrfFailed
from app.db.models import User
from app.db.models._types import utcnow

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_allowed_origin)])

# Generous upper bounds at login: the policy is enforced when passwords are
# set, but login must still reject megabyte payloads before hashing.
LOGIN_USERNAME_MAX = 64
LOGIN_PASSWORD_MAX = 1024


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None
    locked_until: datetime | None

    @classmethod
    def from_model(cls, user: User) -> "UserOut":
        return cls(
            id=user.id,
            username=user.username,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            locked_until=user.locked_until,
        )


class SessionOut(BaseModel):
    user: UserOut
    session_id: uuid.UUID
    access_expires_at: datetime
    refresh_expires_at: datetime


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=LOGIN_USERNAME_MAX)
    password: str = Field(min_length=1, max_length=LOGIN_PASSWORD_MAX)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=LOGIN_PASSWORD_MAX)
    new_password: str = Field(min_length=1, max_length=MAX_LENGTH)


def _session_out(issued: IssuedSession) -> SessionOut:
    return SessionOut(
        user=UserOut.from_model(issued.user),
        session_id=issued.session.id,
        access_expires_at=issued.tokens.access_expires_at,
        refresh_expires_at=issued.tokens.refresh_expires_at,
    )


@router.post("/login", response_model=SessionOut)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    auth: AuthServiceDep,
    settings: SettingsDep,
) -> SessionOut:
    issued = await auth.login(body.username, body.password, anonymous_actor(request))
    set_session_cookies(response, issued.tokens, settings, now=utcnow())
    return _session_out(issued)


@router.post("/refresh", response_model=SessionOut)
async def refresh(
    request: Request, response: Response, auth: AuthServiceDep, settings: SettingsDep
) -> SessionOut:
    token = request.cookies.get(cookie_names(settings).refresh)
    issued = await auth.refresh(token, anonymous_actor(request))
    set_session_cookies(response, issued.tokens, settings, now=utcnow())
    return _session_out(issued)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request, auth: AuthServiceDep, audit: AuditDep, settings: SettingsDep
) -> Response:
    names = cookie_names(settings)
    found = await auth.find_session_for_logout(
        request.cookies.get(names.access), request.cookies.get(names.refresh)
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    if found is not None:
        session, user = found
        # Logout changes state, so it needs the CSRF token like any other
        # write; otherwise any site could log users out.
        reason = csrf_failure_reason(request, session.csrf_token_hash, settings)
        if reason is not None:
            await audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=user_actor(anonymous_actor(request), user, session.id),
                outcome=Outcome.DENIED,
                target="POST /api/v1/auth/logout",
                reason=reason,
            )
            raise CsrfFailed
        await auth.logout(session, user, anonymous_actor(request))
    clear_session_cookies(response, settings)
    return response


@router.get("/me", response_model=UserOut)
async def me(principal: PrincipalDep, auth: AuthServiceDep) -> UserOut:
    user = await auth.get_user(principal.user_id)
    return UserOut.from_model(user)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest, principal: PrincipalDep, auth: AuthServiceDep
) -> Response:
    await auth.change_password(
        principal.user_id,
        principal.session_id,
        body.current_password,
        body.new_password,
        principal.actor,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
