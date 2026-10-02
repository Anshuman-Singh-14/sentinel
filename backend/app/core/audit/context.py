"""Who is acting: user context from requests, system context from the process.

03-logging-audit.md section 2. The client IP comes from
``RequestContextMiddleware``, which applies the trusted-proxy rules once per
request, so the audit log and the access log always agree on the source IP.
"""

import socket
import uuid
from dataclasses import dataclass, replace
from functools import lru_cache

from starlette.requests import HTTPConnection

from app.core.audit.actions import ActorType
from app.core.logging.context import process_user

USER_AGENT_MAX_LENGTH = 512


@dataclass(frozen=True)
class Actor:
    actor_type: ActorType
    user_id: uuid.UUID | None = None
    username: str | None = None
    role: str | None = None
    session_id: uuid.UUID | None = None
    source_ip: str | None = None
    user_agent: str | None = None

    def as_user(
        self, *, user_id: uuid.UUID, username: str, role: str, session_id: uuid.UUID | None
    ) -> "Actor":
        return replace(
            self,
            actor_type=ActorType.USER,
            user_id=user_id,
            username=username,
            role=role,
            session_id=session_id,
        )


SYSTEM_ACTOR = Actor(actor_type=ActorType.SYSTEM)


@dataclass(frozen=True)
class SystemIdentity:
    service: str
    hostname: str
    process_user: str


@lru_cache
def system_identity(service: str) -> SystemIdentity:
    # Stdlib only, never a shell (CLAUDE.md rule 1).
    return SystemIdentity(
        service=service, hostname=socket.gethostname(), process_user=process_user()
    )


def client_ip(connection: HTTPConnection) -> str | None:
    """The client IP resolved by the middleware (trusted-proxy aware)."""
    value = connection.scope.get("state", {}).get("client_ip")
    if isinstance(value, str):
        return value
    return connection.client.host if connection.client else None


def anonymous_actor(connection: HTTPConnection) -> Actor:
    user_agent = connection.headers.get("user-agent")
    return Actor(
        actor_type=ActorType.ANONYMOUS,
        source_ip=client_ip(connection),
        user_agent=user_agent[:USER_AGENT_MAX_LENGTH] if user_agent else None,
    )
