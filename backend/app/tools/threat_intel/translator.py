"""Reputation results -> findings, with the source named on every one.

Severity rules are documented in engine/knowledge/threat_intel.yaml and are
quoted in each finding's rationale, so a reader can see exactly why a
provider's number became HIGH or LOW.
"""

from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Confidence, Finding, FindingStatus, Severity
from app.engine.severity import sort_by_severity
from app.tools.threat_intel.indicators import hash_type
from app.tools.threat_intel.providers.base import Reputation, Verdict

ABUSEIPDB_RULE = "AbuseIPDB score >= 75 is HIGH, 25-74 MEDIUM, 1-24 LOW, 0 INFO."
VIRUSTOTAL_RULE = (
    "VirusTotal: 3 or more vendors flagging malicious is HIGH, 1-2 MEDIUM, "
    "suspicious only LOW, none INFO."
)
WHAT = {
    "ip": "Traffic to or from this address has been reported as hostile (scanning, "
    "brute force, spam, malware hosting or command-and-control).",
    "domain": "This domain has been associated with phishing, malware or other abuse.",
    "hash": "A file with exactly this content has been identified as malicious by "
    "security vendors.",
}


def _finding(
    key: str,
    *,
    category: str,
    status: FindingStatus,
    severity: Severity | None = None,
    confidence: Confidence = Confidence.HIGH,
    evidence: dict[str, Any] | None = None,
    extra_references: list[str] | None = None,
    **values: object,
) -> Finding:
    entry = get_knowledge_base().get(key)
    return Finding(
        item=entry.render("title", **values)[:300],
        category=category,
        status=status,
        severity=severity or entry.severity,
        severity_rationale=entry.render("severity_rationale", **values),
        confidence=confidence,
        explanation=entry.render("explanation", **values),
        remediation=entry.render("remediation", **values),
        evidence=evidence or {},
        references=[*(extra_references or []), *entry.references],
    )


def _abuseipdb(rep: Reputation) -> tuple[Severity, Confidence, str, str, str]:
    score = rep.score or 0
    d = rep.details
    reports, reporters = d.get("total_reports", 0), d.get("distinct_reporters", 0)
    metric = (
        f"AbuseIPDB abuse confidence score {score}/100 from {reports} report(s) "
        f"by {reporters} distinct reporter(s) in the last 90 days"
    )
    if score >= 75:
        severity = Severity.HIGH
    elif score >= 25:
        severity = Severity.MEDIUM
    elif score >= 1:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    confidence = (
        Confidence.HIGH
        if reporters >= 5
        else Confidence.MEDIUM
        if reporters >= 2
        else Confidence.LOW
    )
    headline = f"abuse score {score}/100, {reports} report(s)"
    if severity is Severity.INFO:
        headline = f"has no abuse reports in the last 90 days (score {score}/100)"
        confidence = Confidence.MEDIUM
    return severity, confidence, metric, ABUSEIPDB_RULE, headline


def _virustotal(rep: Reputation) -> tuple[Severity, Confidence, str, str, str]:
    engines: dict[str, int] = rep.details.get("engines", {})
    malicious, suspicious = engines.get("malicious", 0), engines.get("suspicious", 0)
    total = sum(engines.values())
    metric = (
        f"VirusTotal: {malicious} of {total} vendors flag it as malicious, "
        f"{suspicious} as suspicious"
    )
    if malicious >= 3:
        severity = Severity.HIGH
    elif malicious >= 1:
        severity = Severity.MEDIUM
    elif suspicious >= 1:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    confidence = (
        Confidence.HIGH
        if malicious >= 5
        else Confidence.MEDIUM
        if malicious >= 3
        else Confidence.LOW
    )
    headline = f"{malicious}/{total} vendors say malicious"
    if severity is Severity.INFO:
        headline = f"no vendor flags it ({total} vendors checked)"
        confidence = Confidence.MEDIUM
    return severity, confidence, metric, VIRUSTOTAL_RULE, headline


def _reputation_finding(rep: Reputation) -> Finding:
    severity, confidence, metric, rule, headline = (
        _abuseipdb(rep) if rep.provider == "abuseipdb" else _virustotal(rep)
    )
    what = WHAT.get(rep.kind, "")
    if rep.kind == "hash":
        what += f" ({hash_type(rep.indicator).upper()})"
    evidence = {
        "source": rep.provider_name,
        "verdict": rep.verdict.value,
        "score": rep.score,
        "last_seen": rep.last_seen,
        "categories": rep.categories,
        **rep.details,
    }
    common: dict[str, Any] = {
        "indicator": rep.indicator,
        "provider": rep.provider_name,
        "headline": headline,
        "metric": metric,
        "rule": rule,
        "link": rep.link or "",
        "what_it_means": what,
    }
    if severity is Severity.INFO:
        return _finding(
            "threat_intel.clean",
            category="THREAT_INTEL",
            status=FindingStatus.PASS,
            confidence=confidence,
            evidence=evidence,
            extra_references=[rep.link] if rep.link else None,
            **common,
        )
    return _finding(
        "threat_intel.flagged",
        category="THREAT_INTEL",
        status=FindingStatus.DETECTED,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        extra_references=[rep.link] if rep.link else None,
        **common,
    )


def _shodan_finding(rep: Reputation) -> Finding:
    d = rep.details
    ports = ", ".join(str(p) for p in d.get("open_ports", [])) or "none listed"
    values: dict[str, Any] = {
        "indicator": rep.indicator,
        "ports": ports,
        "port_count": len(d.get("open_ports", [])),
        "org": d.get("org") or "unknown",
        "last_seen": rep.last_seen or "unknown",
        "link": rep.link or "",
    }
    evidence = {
        "source": rep.provider_name,
        "last_seen": rep.last_seen,
        "tags": rep.categories,
        **d,
    }
    refs = [rep.link] if rep.link else None
    if d.get("vulns"):
        return _finding(
            "threat_intel.exposure_vulns",
            category="EXPOSURE",
            status=FindingStatus.DETECTED,
            confidence=Confidence.LOW,
            evidence=evidence,
            extra_references=[*(refs or []), *d["vulns"][:5]],
            vuln_count=len(d["vulns"]),
            vulns=", ".join(d["vulns"]),
            **values,
        )
    return _finding(
        "threat_intel.exposure_ports",
        category="EXPOSURE",
        status=FindingStatus.INFO,
        evidence=evidence,
        extra_references=refs,
        **values,
    )


def translate(raw: RawOutput) -> list[Finding]:
    providers = raw.get("providers", [])
    findings = [
        _finding(
            "threat_intel.summary",
            category="THREAT_INTEL",
            status=FindingStatus.INFO,
            evidence={
                "providers": [p["name"] for p in providers],
                "lookups": raw.get("lookups_planned", 0),
                "cache_hits": raw.get("cache_hits", 0),
                "failed_lookups": len(raw.get("failures", [])),
            },
            indicator_count=len(raw.get("indicators", [])),
            provider_names=", ".join(p["name"] for p in providers) or "no provider",
            lookups=raw.get("lookups_planned", 0),
            cache_hits=raw.get("cache_hits", 0),
        )
    ]
    for indicator in raw.get("indicators", []):
        if not indicator.get("lookup"):
            findings.append(
                _finding(
                    "threat_intel.skipped_private",
                    category="THREAT_INTEL",
                    status=FindingStatus.INFO,
                    evidence={"indicator": indicator["value"], "reason": indicator["skip_reason"]},
                    indicator=indicator["value"],
                )
            )
    for data in raw.get("results", []):
        rep = Reputation.from_dict(data)
        if rep.verdict is Verdict.NOT_FOUND:
            findings.append(
                _finding(
                    "threat_intel.not_found",
                    category="THREAT_INTEL",
                    status=FindingStatus.INFO,
                    confidence=Confidence.MEDIUM,
                    evidence={"source": rep.provider_name, "link": rep.link},
                    indicator=rep.indicator,
                    provider=rep.provider_name,
                )
            )
        elif rep.provider == "shodan":
            findings.append(_shodan_finding(rep))
        else:
            findings.append(_reputation_finding(rep))
    return sort_by_severity(findings)
