"""The standard result schema every backend tool returns (CLAUDE.md rule 6).

These models are the contract between tools, storage, the API, the frontend
and the report exporters. See ``docs/spec/01-architecture.md``, section
"Standard result schema".
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.core.ids import uuid7


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Ordering weight: INFO=0 … CRITICAL=4."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


class FindingStatus(StrEnum):
    PASS = "PASS"  # noqa: S105  (a check outcome, not a password)
    FAIL = "FAIL"
    MISSING = "MISSING"
    WEAK = "WEAK"
    DETECTED = "DETECTED"
    CHANGED = "CHANGED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    ERROR = "ERROR"
    INFO = "INFO"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ToolCategory(StrEnum):
    RECON = "RECON"
    WEB = "WEB"
    INTEL = "INTEL"
    DIAGNOSTIC = "DIAGNOSTIC"
    FORENSIC = "FORENSIC"


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"

    @property
    def is_terminal(self) -> bool:
        return self not in (RunStatus.QUEUED, RunStatus.RUNNING)


class Finding(BaseModel):
    """One educational finding: what was found, why it matters, how to fix it."""

    model_config = ConfigDict(extra="forbid")

    finding_id: UUID = Field(default_factory=uuid7)
    item: str = Field(min_length=1, max_length=300)
    category: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    status: FindingStatus
    severity: Severity
    # Every severity must be justified against documented criteria (engine/severity.py).
    severity_rationale: str = Field(min_length=1)
    confidence: Confidence = Confidence.HIGH
    explanation: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ToolError(BaseModel):
    """A user-safe error description. Internal detail stays in the server log."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class SeveritySummary(BaseModel):
    total: int
    by_severity: dict[Severity, int]


def summarize(findings: list[Finding]) -> SeveritySummary:
    counts = dict.fromkeys(reversed(_SEVERITY_ORDER), 0)  # CRITICAL first, as in the spec
    for finding in findings:
        counts[finding.severity] += 1
    return SeveritySummary(total=len(findings), by_severity=counts)


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    tool_id: str
    tool_name: str
    tool_version: str
    target: str | None = None
    initiated_by: str | None = None
    status: RunStatus
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: int | None = None
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    # Derived from findings rather than stored, so it can never disagree with them.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def summary(self) -> SeveritySummary:
        return summarize(self.findings)
