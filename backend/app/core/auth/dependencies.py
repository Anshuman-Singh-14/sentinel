"""FastAPI dependencies for authentication and role-based access control.

Usage in a router::

    @router.get("/things", dependencies=[Depends(require_viewer)])
    async def list_things(): ...

    @router.post("/things")
    async def create_thing(principal: Annotated[Principal, Depends(require_analyst)]): ...

``require_*`` are module-level singletons so FastAPI caches each one per
request: a route that uses the same dependency twice resolves it once.
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.audit import Actor, AuditAction, AuditService, Outcome, get_audit_service
from app.core.audit.context import anonymous_actor
from app.core.auth.cookies import cookie_names
from app.core.auth.csrf import SAFE_METHODS, csrf_failure_reason, origin_failure_reason
from app.core.auth.roles import Role, role_allows
from app.core.auth.service import AuthService, user_actor
from app.core.errors import AuthenticationRequired, CsrfFailed, PermissionDenied
from app.core.http import route_template
from app.core.logging.context import bind_context
from app.core.ratelimit import RateLimiter, get_rate_limiter
from app.db.session import get_session

SessionDep = Annotated[AsyncSession, Depends(get_session)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]


def get_auth_service(
    db: SessionDep, audit: AuditDep, limiter: LimiterDep, settings: SettingsDep
) -> AuthService:
    return AuthService(db, audit, limiter, settings)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of the current request."""

    user_id: uuid.UUID
    username: str
    role: Role
    session_id: uuid.UUID
    actor: Actor


def _route(request: Request) -> str:
    return f"{request.method} {route_template(request.scope) or '<unmatched>'}"


async def get_principal(
    request: Request, auth: AuthServiceDep, audit: AuditDep, settings: SettingsDep
) -> Principal:
    result = await auth.authenticate(request.cookies.get(cookie_names(settings).access))
    if result is None:
        raise AuthenticationRequired
    session, user = result
    actor = user_actor(anonymous_actor(request), user, session.id)

    if request.method not in SAFE_METHODS:
        reason = csrf_failure_reason(request, session.csrf_token_hash, settings)
        if reason is not None:
            await audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=actor,
                outcome=Outcome.DENIED,
                target=_route(request),
                reason=reason,
            )
            raise CsrfFailed

    # Every later log line of this request carries who made it.
    bind_context(
        user_id=str(user.id), username=user.username, role=user.role, session_id=str(session.id)
    )
    return Principal(
        user_id=user.id,
        username=user.username,
        role=user.role_enum,
        session_id=session.id,
        actor=actor,
    )


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require_role(minimum: Role) -> Callable[..., Awaitable[Principal]]:
    async def dependency(request: Request, principal: PrincipalDep, audit: AuditDep) -> Principal:
        if not role_allows(principal.role, minimum):
            await audit.record(
                AuditAction.AUTH_ACCESS_DENIED,
                actor=principal.actor,
                outcome=Outcome.DENIED,
                target=_route(request),
                reason="insufficient_role",
                details={"required_role": minimum.value, "role": principal.role.value},
            )
            raise PermissionDenied
        return principal

    dependency.__name__ = f"require_{minimum.value}"
    return dependency


require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.ANALYST)
require_admin = require_role(Role.ADMIN)

ViewerDep = Annotated[Principal, Depends(require_viewer)]
AnalystDep = Annotated[Principal, Depends(require_analyst)]
AdminDep = Annotated[Principal, Depends(require_admin)]


async def require_allowed_origin(request: Request, settings: SettingsDep) -> None:
    """Origin check for unauthenticated state-changing endpoints (login, refresh).

    Blocks login CSRF. Authenticated routes get the full check in get_principal.
    """
    if request.method in SAFE_METHODS:
        return
    if origin_failure_reason(request, settings) is not None:
        raise CsrfFailed
