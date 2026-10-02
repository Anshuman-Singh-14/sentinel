"""The runner turns every outcome into a ToolResult, never an exception."""

import asyncio

import pytest
from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import ProviderError
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.runner import execute_tool
from app.engine.schemas import (
    Finding,
    FindingStatus,
    RunStatus,
    Severity,
    ToolCategory,
    ToolResult,
)
from tests.conftest import LogCapture


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1)
    behaviour: str = "ok"


class ScenarioTool(BaseTool[Params]):
    tool_id = "scenario"
    name = "Scenario"
    description = "Behaves as instructed, for testing the runner."
    version = "2.1.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = Params
    soft_time_limit = 1
    hard_time_limit = 2

    async def run(self, params: Params, ctx: ToolContext) -> RawOutput:
        match params.behaviour:
            case "slow":
                await asyncio.sleep(10)
            case "crash":
                raise RuntimeError("internal detail: password=SuperSecret99")
            case "provider":
                raise ProviderError("Threat feed unavailable.")
            case "cancel":
                await ctx.raise_if_cancelled()
            case "partial":
                ctx.add_error("provider_timeout", "VirusTotal did not respond.")
        await ctx.report_progress(150, "done")  # clamped to 100
        return {"host": params.host}

    def translate(self, raw: RawOutput, params: Params) -> list[Finding]:
        return [
            Finding(
                item=raw["host"],
                category="TEST",
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                severity_rationale="Test.",
                explanation="Test.",
                remediation="None.",
            )
        ]

    def target_of(self, params: Params) -> str:
        return params.host


async def run(behaviour: str = "ok") -> ToolResult:
    return await execute_tool(
        ScenarioTool(), {"host": "example.com", "behaviour": behaviour}, run_id=uuid7()
    )


async def test_successful_run() -> None:
    progress: list[tuple[int, str]] = []

    async def on_progress(pct: int, message: str) -> None:
        progress.append((pct, message))

    run_id = uuid7()
    ctx = ToolContext(run_id=run_id, logger=get_logger("test"), progress_callback=on_progress)
    result = await execute_tool(
        ScenarioTool(), {"host": "example.com"}, run_id=run_id, initiated_by="analyst01", ctx=ctx
    )

    assert result.status == RunStatus.COMPLETED
    assert result.run_id == run_id
    assert result.tool_id == "scenario"
    assert result.tool_version == "2.1.0"
    assert result.target == "example.com"
    assert result.initiated_by == "analyst01"
    assert result.raw_data == {"host": "example.com"}
    assert len(result.findings) == 1
    assert result.errors == []
    assert result.completed_at is not None and result.completed_at >= result.started_at
    assert result.duration_ms is not None and result.duration_ms >= 0
    assert progress == [(100, "done")]


async def test_invalid_params_fail_without_running() -> None:
    result = await execute_tool(ScenarioTool(), {"host": "", "extra": 1}, run_id=uuid7())

    assert result.status == RunStatus.FAILED
    assert [e.code for e in result.errors] == ["invalid_params"]
    assert result.target is None


async def test_accepts_already_validated_model() -> None:
    result = await execute_tool(ScenarioTool(), Params(host="h"), run_id=uuid7())
    assert result.status == RunStatus.COMPLETED


async def test_timeout_becomes_timed_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ScenarioTool, "soft_time_limit", 0.05)
    result = await run("slow")

    assert result.status == RunStatus.TIMED_OUT
    assert [e.code for e in result.errors] == ["tool_timeout"]


async def test_crash_is_generic_and_logged(logs: LogCapture) -> None:
    result = await run("crash")

    assert result.status == RunStatus.FAILED
    (error,) = result.errors
    assert error.code == "tool_error"
    assert "SuperSecret99" not in error.message
    assert "RuntimeError" not in error.message
    (logged,) = logs.events("tool.run.crashed")
    assert "RuntimeError" in logged["exception"]
    assert logged["tool_id"] == "scenario"
    assert "SuperSecret99" not in logs.text


async def test_sentinel_error_keeps_code_and_message() -> None:
    result = await run("provider")

    assert result.status == RunStatus.FAILED
    assert result.errors[0].code == "provider_error"
    assert result.errors[0].message == "Threat feed unavailable."


async def test_cooperative_cancellation() -> None:
    async def cancelled() -> bool:
        return True

    run_id = uuid7()
    ctx = ToolContext(run_id=run_id, logger=get_logger("test"), cancel_check=cancelled)
    result = await execute_tool(
        ScenarioTool(), {"host": "h", "behaviour": "cancel"}, run_id=run_id, ctx=ctx
    )

    assert result.status == RunStatus.CANCELLED
    assert result.findings == []


async def test_partial_results_keep_findings_and_errors() -> None:
    result = await run("partial")

    assert result.status == RunStatus.COMPLETED
    assert len(result.findings) == 1
    assert [e.code for e in result.errors] == ["provider_timeout"]


async def test_run_logs_carry_run_id(logs: LogCapture) -> None:
    run_id = uuid7()
    await execute_tool(ScenarioTool(), {"host": "h"}, run_id=run_id)

    started, completed = logs.events("tool.run.started"), logs.events("tool.run.completed")
    assert started[0]["run_id"] == completed[0]["run_id"] == str(run_id)
    assert completed[0]["finding_count"] == 1
