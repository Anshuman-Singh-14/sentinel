from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.core.ids import uuid7
from app.engine.schemas import (
    Finding,
    FindingStatus,
    RunStatus,
    Severity,
    ToolResult,
    summarize,
)


def make_finding(severity: Severity = Severity.INFO, **overrides: object) -> Finding:
    data: dict[str, object] = {
        "item": "Strict-Transport-Security (HSTS)",
        "category": "HTTP_HEADERS",
        "status": FindingStatus.MISSING,
        "severity": severity,
        "severity_rationale": "Missing HSTS permits SSL stripping (OWASP).",
        "explanation": "HSTS tells browsers to only use HTTPS.",
        "remediation": "Add Strict-Transport-Security.",
    }
    data.update(overrides)
    return Finding.model_validate(data)


def test_result_serialises_to_spec_shape() -> None:
    result = ToolResult(
        run_id=uuid7(),
        tool_id="header_tls",
        tool_name="HTTP Security Header & TLS Checker",
        tool_version="1.0.0",
        target="example.com",
        initiated_by="analyst01",
        status=RunStatus.COMPLETED,
        started_at=datetime.now(UTC),
        findings=[make_finding(Severity.HIGH), make_finding(Severity.MEDIUM), make_finding()],
    )
    body = result.model_dump(mode="json")

    assert set(body) == {
        "run_id", "tool_id", "tool_name", "tool_version", "target", "initiated_by", "status",
        "started_at", "completed_at", "duration_ms", "summary", "findings", "errors", "raw_data",
    }  # fmt: skip
    assert body["summary"] == {
        "total": 3,
        "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 1},
    }
    assert set(body["findings"][0]) == {
        "finding_id", "item", "category", "status", "severity", "severity_rationale",
        "confidence", "explanation", "remediation", "evidence", "references", "raw_data",
    }  # fmt: skip


def test_summary_of_no_findings() -> None:
    summary = summarize([])
    assert summary.total == 0
    assert set(summary.by_severity.values()) == {0}


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_finding(unexpected="x")


@pytest.mark.parametrize("category", ["http_headers", "1ABC", "HTTP-HEADERS", ""])
def test_finding_category_format(category: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(category=category)


def test_finding_requires_rationale() -> None:
    with pytest.raises(ValidationError):
        make_finding(severity_rationale="")


def test_severity_ranking() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank


def test_terminal_run_states() -> None:
    assert not RunStatus.QUEUED.is_terminal
    assert not RunStatus.RUNNING.is_terminal
    assert all(
        s.is_terminal
        for s in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.TIMED_OUT)
    )
