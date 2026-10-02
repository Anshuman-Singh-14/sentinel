"""Framework-side execution of a tool: validate, run, translate, wrap.

This runs in-process. Phase 5's Celery task is a thin layer on top that adds
persistence, audit events and progress publishing. Keeping this core free of
Celery makes it easy to unit test.

Failures never escape as exceptions. Every outcome becomes a ``ToolResult``
with a status and user-safe ``errors[]`` (CLAUDE.md rules 6 and 8).
"""

import asyncio
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from pydantic import BaseModel, ValidationError

from app.core.errors import SentinelError
from app.core.logging import get_logger
from app.engine.base_tool import BaseTool, RunCancelled, ToolContext
from app.engine.schemas import Finding, RunStatus, ToolError, ToolResult

logger = get_logger("sentinel.engine")


async def execute_tool(
    tool: BaseTool[Any],
    params: Mapping[str, Any] | BaseModel,
    *,
    run_id: UUID,
    initiated_by: str | None = None,
    ctx: ToolContext | None = None,
) -> ToolResult:
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    context = ctx or ToolContext(run_id=run_id, logger=logger.bind(run_id=str(run_id)))

    def result(
        status: RunStatus,
        *,
        target: str | None = None,
        findings: list[Finding] | None = None,
        errors: list[ToolError] | None = None,
        raw: dict[str, Any] | None = None,
    ) -> ToolResult:
        return ToolResult(
            run_id=run_id,
            tool_id=tool.tool_id,
            tool_name=tool.name,
            tool_version=tool.version,
            target=target,
            initiated_by=initiated_by,
            status=status,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            duration_ms=round((time.perf_counter() - started) * 1000),
            findings=findings or [],
            errors=[*context.errors, *(errors or [])],
            raw_data=raw or {},
        )

    with structlog.contextvars.bound_contextvars(run_id=str(run_id), tool_id=tool.tool_id):
        # Validate again even though the API already did: queued messages and
        # playbook step references are inputs too (defence in depth).
        try:
            validated = tool.params_model.model_validate(
                params.model_dump() if isinstance(params, BaseModel) else params
            )
        except ValidationError as exc:
            logger.warning("tool.run.invalid_params", error_count=exc.error_count())
            return result(
                RunStatus.FAILED,
                errors=[ToolError(code="invalid_params", message="Tool parameters are invalid.")],
            )

        target = tool.target_of(validated)
        logger.info("tool.run.started", target=target)
        try:
            # The soft limit ends the run gracefully with TIMED_OUT. Celery's
            # hard limit (Phase 5) is the backstop if a tool ignores cancellation.
            async with asyncio.timeout(tool.soft_time_limit):
                raw = await tool.run(validated, context)
            findings = tool.translate(raw, validated)
        except TimeoutError:
            logger.warning("tool.run.timed_out", soft_time_limit=tool.soft_time_limit)
            return result(
                RunStatus.TIMED_OUT,
                target=target,
                errors=[
                    ToolError(code="tool_timeout", message="The tool exceeded its time limit.")
                ],
            )
        except RunCancelled:
            logger.info("tool.run.cancelled")
            return result(RunStatus.CANCELLED, target=target)
        except SentinelError as exc:
            logger.warning("tool.run.failed", error_code=exc.code)
            return result(
                RunStatus.FAILED,
                target=target,
                errors=[ToolError(code=exc.code, message=exc.message)],
            )
        except Exception:  # any tool bug must become a FAILED result, never a crash
            logger.exception("tool.run.crashed")
            return result(
                RunStatus.FAILED,
                target=target,
                errors=[ToolError(code="tool_error", message="The tool failed unexpectedly.")],
            )

        logger.info("tool.run.completed", finding_count=len(findings))
        return result(RunStatus.COMPLETED, target=target, findings=findings, raw=raw)
