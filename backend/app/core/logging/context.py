"""Correlation and system context attached to every log line.

Request-scoped values (``request_id``, ``user_id``, ``run_id``...) live in
``contextvars`` through structlog, so they follow a request across ``await``
points and are restored inside Celery tasks (see ``app.core.tasks.context``).
"""

import getpass
import os
import socket
from functools import lru_cache
from typing import Any

import structlog
from structlog.typing import EventDict, WrappedLogger

from app import __version__

# Present on every line, with None when not applicable. A stable schema makes
# logs easy to query ("request_id on every line", Phase 1 acceptance).
STANDARD_CONTEXT_FIELDS = ("request_id", "user_id", "run_id")


@lru_cache
def process_user() -> str:
    # Stdlib only, never a shell (03-logging-audit.md section 2). getuser() can
    # fail for a UID with no passwd entry, so fall back to the numeric UID.
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        getuid = getattr(os, "getuid", None)
        return str(getuid()) if getuid else "unknown"


class SystemContextProcessor:
    """Adds the identity of the process doing the work (who, where, which build)."""

    def __init__(self, *, service: str, environment: str) -> None:
        self._static = {
            "service": service,
            "environment": environment,
            "app_version": __version__,
            "hostname": socket.gethostname(),
            "process_user": process_user(),
        }

    def __call__(self, logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
        for key, value in self._static.items():
            event_dict.setdefault(key, value)
        # The PID is read per call because Celery prefork workers fork after setup.
        event_dict.setdefault("pid", os.getpid())
        for key in STANDARD_CONTEXT_FIELDS:
            event_dict.setdefault(key, None)
        return event_dict


def bind_context(**values: Any) -> None:
    structlog.contextvars.bind_contextvars(**values)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()


def current_request_id() -> str | None:
    value = structlog.contextvars.get_contextvars().get("request_id")
    return value if isinstance(value, str) else None
