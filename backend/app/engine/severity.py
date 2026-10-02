"""Documented severity criteria.

Severity is never chosen ad hoc. Tools call these helpers so every finding's
severity traces back to a published standard, and its ``severity_rationale``
says which one.

* CVE-based findings use the FIRST CVSS v3.1 qualitative rating scale.
* Configuration findings reference OWASP, CWE or NIST guidance in their
  knowledge-base entry (engine/knowledge/*.yaml).
"""

import math
from collections.abc import Iterable

from app.engine.schemas import Finding, Severity

CVSS_V31_SCALE_URL = (
    "https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale"
)

# (lower bound inclusive, severity, label). CVSS scores have one decimal place.
CVSS_V31_BANDS: tuple[tuple[float, Severity, str], ...] = (
    (9.0, Severity.CRITICAL, "9.0-10.0"),
    (7.0, Severity.HIGH, "7.0-8.9"),
    (4.0, Severity.MEDIUM, "4.0-6.9"),
    (0.1, Severity.LOW, "0.1-3.9"),
    (0.0, Severity.INFO, "0.0 (None)"),
)


def _validate_cvss(score: float) -> None:
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS base score must be within 0.0-10.0, got {score!r}")


def _band(score: float) -> tuple[Severity, str]:
    _validate_cvss(score)
    for lower, severity, label in CVSS_V31_BANDS:
        if score >= lower:
            return severity, label
    raise AssertionError("unreachable: 0.0 band matches every valid score")  # pragma: no cover


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS v3.1 base score to a severity. CVSS 0.0 ("None") maps to INFO."""
    return _band(score)[0]


def cvss_rationale(score: float, cve_id: str | None = None) -> str:
    severity, label = _band(score)
    subject = f"{cve_id} has a CVSS v3.1 base score of" if cve_id else "CVSS v3.1 base score"
    return (
        f"{subject} {score:.1f}, which falls in the {severity.value} band ({label}) "
        f"of the FIRST CVSS v3.1 qualitative severity rating scale."
    )


def highest_severity(severities: Iterable[Severity]) -> Severity | None:
    return max(severities, key=lambda s: s.rank, default=None)


def sort_by_severity(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first. The sort is stable, so equal severities keep tool order."""
    return sorted(findings, key=lambda f: f.severity.rank, reverse=True)
