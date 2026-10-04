"""Building a report document from a tool run (pure; no database)."""

import uuid
from datetime import UTC, datetime

from app.db.models import FindingRow, ToolRun
from app.reports.document import from_tool_run

WHEN = datetime(2026, 10, 4, 9, 0, tzinfo=UTC)


def _run(status: str = "COMPLETED") -> ToolRun:
    return ToolRun(
        id=uuid.uuid4(),
        tool_id="echo",
        tool_name="Echo",
        tool_version="1.0.0",
        status=status,
        params={"message": "hi"},
        target="hi",
        user_id=uuid.uuid4(),
        username="ana",
        created_at=WHEN,
        started_at=WHEN,
        completed_at=WHEN,
        duration_ms=12,
        errors=[{"code": "partial", "message": "Something was skipped."}],
        raw_data={"echoes": ["hi"]},
    )


def _row(run: ToolRun, position: int, item: str, severity: str) -> FindingRow:
    return FindingRow(
        id=uuid.uuid4(),
        run_id=run.id,
        position=position,
        item=item,
        category="DIAGNOSTIC",
        status="INFO",
        severity=severity,
        severity_rationale="r",
        confidence="HIGH",
        explanation="e",
        remediation="m",
        evidence={},
        references=[],
        raw_data={},
    )


def test_tool_run_document_has_findings_sorted_with_provenance() -> None:
    run = _run()
    rows = [_row(run, 0, "Low thing", "LOW"), _row(run, 1, "High thing", "HIGH")]
    doc = from_tool_run(run, rows, report_id=uuid.uuid4(), generated_by="bob", generated_at=WHEN)

    assert doc.subject.kind == "tool_run" and doc.subject.parameters == {"message": "hi"}
    assert [f.item for f in doc.findings] == ["High thing", "Low thing"]
    assert {f.step_id for f in doc.findings} == {"echo"} and doc.findings[0].run_id == run.id
    assert doc.tools[0].version == "1.0.0" and doc.steps == []
    assert doc.risk.highest is not None and doc.risk.highest.value == "HIGH"
    assert doc.risk.headline.endswith("from 1 completed run(s).")
    assert doc.errors == ["Something was skipped."]
    assert doc.raw[0].data == {"echoes": ["hi"]} and doc.generated_by == "bob"


def test_failed_run_reports_partial_coverage() -> None:
    doc = from_tool_run(
        _run("FAILED"), [], report_id=uuid.uuid4(), generated_by="bob", generated_at=WHEN
    )
    assert doc.findings == []
    assert "No findings from 0 completed run(s)." in doc.risk.headline
    assert "coverage is partial" in doc.risk.headline
