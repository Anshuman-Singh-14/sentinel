"""Unified findings across playbook steps: merge, de-duplicate, rank, summarise.

Pure functions. De-duplication key: (category, item, severity),
case-insensitive. The first step to report a finding keeps it; later steps
are listed in ``also_reported_by``, so nothing is silently lost.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from app.engine.schemas import Finding, Severity
from app.playbooks.schemas import AggregatedFinding, RiskSummary

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True, slots=True)
class StepFindings:
    step_id: str
    tool_id: str
    run_id: uuid.UUID
    findings: list[Finding]


def merge(steps: Iterable[StepFindings]) -> list[AggregatedFinding]:
    merged: dict[tuple[str, str, Severity], AggregatedFinding] = {}
    for step in steps:
        for finding in step.findings:
            key = (finding.category.lower(), finding.item.strip().lower(), finding.severity)
            if key in merged:
                existing = merged[key]
                if (
                    step.step_id != existing.step_id
                    and step.step_id not in existing.also_reported_by
                ):
                    existing.also_reported_by.append(step.step_id)
                continue
            merged[key] = AggregatedFinding(
                **finding.model_dump(),
                step_id=step.step_id,
                tool_id=step.tool_id,
                run_id=step.run_id,
            )
    # Stable: equal severities keep step order.
    return sorted(merged.values(), key=lambda f: ORDER.index(f.severity))


def risk_summary(
    findings: list[AggregatedFinding], *, completed_steps: int, failed_steps: int
) -> RiskSummary:
    counts = {severity: 0 for severity in ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    highest = next((s for s in ORDER if counts[s]), None)
    parts = [f"{counts[s]} {s.value.lower()}" for s in ORDER if counts[s]]
    if highest is None:
        headline = f"No findings from {completed_steps} completed step(s)."
    else:
        headline = (
            f"Highest severity {highest.value}: {', '.join(parts)} finding(s) "
            f"from {completed_steps} completed step(s)."
        )
    if failed_steps:
        headline += f" {failed_steps} step(s) did not complete, so coverage is partial."
    return RiskSummary(total=len(findings), by_severity=counts, highest=highest, headline=headline)
