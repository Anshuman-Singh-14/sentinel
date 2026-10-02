"""The echo tool proves the contract end to end: registry -> runner -> ToolResult."""

import pytest

from app.core.ids import uuid7
from app.engine.registry import registry
from app.engine.runner import execute_tool
from app.engine.schemas import RunStatus, Severity


@pytest.fixture(autouse=True)
def _discover() -> None:
    registry.discover()


async def test_echo_produces_educational_finding() -> None:
    result = await execute_tool(
        registry.create("echo"), {"message": "  hello  ", "repeat": 3}, run_id=uuid7()
    )

    assert result.status == RunStatus.COMPLETED
    assert result.raw_data == {"echoes": ["hello"] * 3, "length": 5}
    (finding,) = result.findings
    assert finding.severity == Severity.INFO
    assert "5 characters, repeated 3 time(s)" in finding.explanation
    assert finding.severity_rationale
    assert result.summary.by_severity[Severity.INFO] == 1


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"message": ""},
        {"message": "x" * 501},
        {"message": "x", "repeat": 6},
        {"message": "x", "x": 1},
    ],
)
async def test_echo_rejects_invalid_params(params: dict[str, object]) -> None:
    result = await execute_tool(registry.create("echo"), params, run_id=uuid7())

    assert result.status == RunStatus.FAILED
    assert result.errors[0].code == "invalid_params"
