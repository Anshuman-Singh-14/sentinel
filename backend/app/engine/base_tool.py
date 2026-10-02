"""The tool plugin contract (01-architecture.md, section "Tool plugin contract").

A tool supplies two things: ``run`` (do the work, return raw data) and
``translate`` (turn raw data into educational findings). Everything else
(validation, timing, timeouts, error wrapping, logging, and later persistence,
audit and progress publishing) is handled by the framework, so it is enforced
consistently and never reimplemented per tool.
"""

import inspect
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar
from uuid import UUID

import structlog
from pydantic import BaseModel

from app.core.auth.roles import Role
from app.core.tasks.queues import QUEUES
from app.engine.schemas import Finding, ToolCategory, ToolError

# Raw tool output: JSON-serialisable data, stored alongside the findings for
# advanced users and later re-translation.
RawOutput = dict[str, Any]

ProgressCallback = Callable[[int, str], Awaitable[None]]
CancelCheck = Callable[[], Awaitable[bool]]
# Scope check for a host the tool discovers mid-run (e.g. a redirect target).
# Returns the approved addresses, or raises ScopeDenied. Provided by the
# framework for active tools; the decision and audit happen outside the tool.
ScopeCheck = Callable[[str], Awaitable[tuple[str, ...]]]

_TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class RunCancelled(Exception):  # a control-flow signal, not an error
    """Raised by a tool when ``ctx.is_cancelled()`` reports a cancellation request."""


async def _no_progress(pct: int, message: str) -> None:
    return None


async def _never_cancelled() -> bool:
    return False


@dataclass(slots=True)
class ToolContext:
    """Per-run services handed to a tool. Tools never touch the DB, Celery or Redis."""

    run_id: UUID
    logger: structlog.stdlib.BoundLogger
    progress_callback: ProgressCallback = _no_progress
    cancel_check: CancelCheck = _never_cancelled
    errors: list[ToolError] = field(default_factory=list)
    # For active tools: the addresses the scope guard checked and approved.
    # Tools connect to these and never re-resolve the target name, so DNS
    # cannot change between "checked" and "connected" (rebinding).
    authorized_addresses: tuple[str, ...] = ()
    scope_check: ScopeCheck | None = None

    async def report_progress(self, pct: int, message: str) -> None:
        await self.progress_callback(max(0, min(100, pct)), message)

    async def is_cancelled(self) -> bool:
        return await self.cancel_check()

    async def raise_if_cancelled(self) -> None:
        """Call between units of work (e.g. every N ports) for cooperative cancellation."""
        if await self.cancel_check():
            raise RunCancelled

    def add_error(self, code: str, message: str) -> None:
        """Record a non-fatal problem. The run still completes with partial results.

        Example: one of three threat-intel providers timed out.
        """
        self.errors.append(ToolError(code=code, message=message))


class BaseTool[ParamsT: BaseModel](ABC):
    tool_id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str]  # semver, stored with every result
    category: ClassVar[ToolCategory]
    params_model: ClassVar[type[BaseModel]]
    is_active: ClassVar[bool] = False  # sends traffic to targets, so a scope check is required
    required_role: ClassVar[Role] = Role.ANALYST
    queue: ClassVar[str] = "default"
    soft_time_limit: ClassVar[int] = 30  # seconds: graceful timeout, result is TIMED_OUT
    hard_time_limit: ClassVar[int] = 60  # seconds: Celery kills the task (Phase 5)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate tool metadata at import time, so a bad tool fails at startup."""
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        for attr in ("tool_id", "name", "description", "version", "category", "params_model"):
            if not hasattr(cls, attr):
                raise TypeError(f"{cls.__name__} must define class attribute {attr!r}")
        if not _TOOL_ID_RE.fullmatch(cls.tool_id):
            raise TypeError(
                f"{cls.__name__}.tool_id {cls.tool_id!r} must match {_TOOL_ID_RE.pattern}"
            )
        if not _SEMVER_RE.fullmatch(cls.version):
            raise TypeError(f"{cls.__name__}.version must be semver (x.y.z)")
        if not issubclass(cls.params_model, BaseModel):
            raise TypeError(f"{cls.__name__}.params_model must be a Pydantic model")
        if cls.params_model.model_config.get("extra") != "forbid":
            # Unknown fields are rejected everywhere (04-security.md section 4).
            raise TypeError(f"{cls.__name__}.params_model must set extra='forbid'")
        if cls.queue not in QUEUES:
            raise TypeError(f"{cls.__name__}.queue must be one of {QUEUES}")
        if not 0 < cls.soft_time_limit < cls.hard_time_limit:
            raise TypeError(f"{cls.__name__}: require 0 < soft_time_limit < hard_time_limit")

    @abstractmethod
    async def run(self, params: ParamsT, ctx: ToolContext) -> RawOutput:
        """Do the work. Pure async I/O with timeouts. No framework imports."""

    @abstractmethod
    def translate(self, raw: RawOutput, params: ParamsT) -> list[Finding]:
        """Turn raw output into educational findings (the Translation Engine)."""

    def target_of(self, params: ParamsT) -> str | None:
        """The human-readable target recorded on the result (host, URL...)."""
        return None

    def scope_host(self, params: ParamsT) -> str | None:
        """The host the scope policy must approve (defaults to ``target_of``).

        Differs when the target is a URL: the URL is shown to the user, the
        host is what gets resolved and checked.
        """
        return self.target_of(params)
