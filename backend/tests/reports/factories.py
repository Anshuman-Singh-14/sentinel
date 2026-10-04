"""Report documents for exporter tests, built without a database."""

import uuid
from datetime import UTC, datetime
from typing import Any

from app.engine.schemas import Confidence, FindingStatus, Severity
from app.playbooks.aggregate import risk_summary
from app.playbooks.schemas import AggregatedFinding
from app.reports.document import RawSection, ReportDocument, ReportStep, ReportSubject, ReportTool

WHEN = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
RUN_ID = uuid.UUID("01923456-789a-7bcd-8ef0-123456789abc")


def finding(
    item: str = "Missing Content-Security-Policy",
    severity: Severity = Severity.MEDIUM,
    **overrides: Any,
) -> AggregatedFinding:
    values: dict[str, Any] = {
        "item": item,
        "category": "HEADERS",
        "status": FindingStatus.MISSING,
        "severity": severity,
        "severity_rationale": "OWASP Secure Headers: CSP mitigates XSS.",
        "confidence": Confidence.HIGH,
        "explanation": "The site sends no CSP header.",
        "remediation": "Add a Content-Security-Policy header.",
        "evidence": {"header": None},
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "step_id": "headers",
        "tool_id": "header_tls",
        "run_id": RUN_ID,
    }
    values.update(overrides)
    return AggregatedFinding(**values)


def document(
    findings: list[AggregatedFinding] | None = None,
    *,
    target: str = "lab-https",
    raw: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> ReportDocument:
    items = (
        findings
        if findings is not None
        else [finding("Self-signed certificate", Severity.HIGH), finding()]
    )
    return ReportDocument(
        report_id=uuid.UUID("01923456-789a-7bcd-8ef0-000000000001"),
        title="Web Defensive Audit report",
        generated_at=WHEN,
        generated_by="ana",
        subject=ReportSubject(
            kind="playbook_run",
            id=uuid.UUID("01923456-789a-7bcd-8ef0-000000000002"),
            name="Web Defensive Audit",
            version="1.0.0",
            target=target,
            status="COMPLETED",
            initiated_by="ana",
            created_at=WHEN,
            started_at=WHEN,
            completed_at=WHEN,
            duration_ms=4200,
            parameters={"target": target},
        ),
        tools=[ReportTool(tool_id="header_tls", name="Header & TLS checker", version="1.0.0")],
        steps=[
            ReportStep(
                position=0,
                step_id="headers",
                name="Headers and TLS",
                tool_id="header_tls",
                status="COMPLETED",
                on_failure="continue",
                run_id=RUN_ID,
                error=None,
                started_at=WHEN,
                completed_at=WHEN,
            )
        ],
        risk=risk_summary(items, completed_steps=1, failed_steps=0),
        findings=items,
        errors=errors or [],
        raw=[RawSection(label="Headers and TLS", run_id=RUN_ID, data=raw or {"status": 200})],
    )
