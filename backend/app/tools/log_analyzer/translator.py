"""Detections -> educational findings.

One finding per (rule, source address), most active first, at most
``MAX_PER_RULE`` per rule plus one grouping finding for the rest, so a log
from a large botnet still gives a readable report. Severity escalations
(a root login that succeeded, traversal answered with 2xx, a 5xx-dominated
spike) use their own knowledge entries, so the rationale always matches the
severity shown.
"""

from datetime import datetime
from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Confidence, Finding, FindingStatus
from app.engine.severity import sort_by_severity
from app.tools.log_analyzer.rules import Rule, RuleFile, get_rules

MAX_PER_RULE = 25
UNRECOGNISED_NOTE_RATIO = 0.2


def _when(value: str | None) -> str:
    if not value:
        return "an unknown time"
    return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def _finding(
    key: str,
    *,
    category: str,
    status: FindingStatus = FindingStatus.DETECTED,
    confidence: Confidence = Confidence.HIGH,
    evidence: dict[str, Any] | None = None,
    values: dict[str, object] | None = None,
    **more: object,
) -> Finding:
    values = {**(values or {}), **more}
    entry = get_knowledge_base().get(key)
    return Finding(
        item=entry.render("title", **values)[:300],
        category=category,
        status=status,
        severity=entry.severity,
        severity_rationale=entry.render("severity_rationale", **values),
        confidence=confidence,
        explanation=entry.render("explanation", **values),
        remediation=entry.render("remediation", **values),
        evidence=evidence or {},
        references=list(entry.references),
    )


def _detection_finding(rule: Rule, det: dict[str, Any]) -> Finding:
    details: dict[str, Any] = det["details"]
    values: dict[str, object] = {
        "ip": det["key"],
        "count": det["count"],
        "threshold": rule.threshold,
        "window_seconds": rule.window_seconds or "",
        "first_seen": _when(det["first_seen"]),
        "last_seen": _when(det["last_seen"]),
    }
    evidence: dict[str, Any] = {
        "rule_id": rule.id,
        "source_ip": det["key"],
        "event_type": ", ".join(rule.events),
        "count": det["count"],
        "first_seen": det["first_seen"],
        "last_seen": det["last_seen"],
        "threshold": rule.threshold,
        **({"window_seconds": rule.window_seconds} if rule.window_seconds else {}),
        **details,
    }
    key = rule.knowledge
    confidence = Confidence.HIGH

    if rule.detector == "burst":
        values["peak"] = details.get("peak_in_window", "?")
        users = details.get("users") or []
        values["users_text"] = (
            f", trying user names such as {', '.join(users[:5])}" if users else ""
        )
    elif rule.detector == "distinct":
        values["distinct"] = details.get("distinct_values", 0)
        values["values"] = ", ".join((details.get("values") or [])[:5])
    elif rule.detector == "sequence":
        successes = details.get("successes") or []
        first = successes[0] if successes else {}
        values["failures"] = first.get("failures_before", rule.threshold)
        values["successes_text"] = "; ".join(
            f"as {s['user']} via {s['method'] or 'unknown method'}" for s in successes
        )
        # A typo then success is common; repeated guessing then success is not.
        confidence = Confidence.MEDIUM
    elif rule.detector == "match":
        samples = details.get("samples") or []
        values["sample"] = samples[0] if samples else "(none)"
        values["matched"] = ", ".join(details.get("matched") or [])
        values["techniques"] = values["matched"]
        if rule.id == "root_login_attempt":
            accepted = (details.get("by_event") or {}).get("ssh_accepted", 0)
            values["accepted"] = accepted
            if accepted:
                key = "log_analyzer.root_login_success"
        if rule.builtin == "path_traversal":
            successful = details.get("successful_responses", 0)
            values["successful"] = successful
            if successful:
                key = "log_analyzer.path_traversal_success"
        if rule.id == "scanner_user_agent":
            confidence = Confidence.MEDIUM  # the user agent is self-declared
    elif rule.detector == "spike":
        classes: dict[str, int] = details.get("by_status_class") or {}
        values["total"] = details.get("total_requests", 0)
        values["bucket_seconds"] = details.get("bucket_seconds", "")
        values["classes"] = ", ".join(f"{v} x {k}" for k, v in classes.items())
        evidence.pop("source_ip", None)
        evidence["window_start"] = det["key"]
        if classes.get("5xx", 0) * 2 >= det["count"]:
            key = "log_analyzer.error_spike_5xx"

    return _finding(
        key, category=rule.category, confidence=confidence, evidence=evidence, values=values
    )


def translate(raw: RawOutput, rules: RuleFile | None = None) -> list[Finding]:
    rules = rules or get_rules()
    by_id = {rule.id: rule for rule in rules.rules}
    stats: dict[str, Any] = raw["stats"]
    parser_title = raw["parser"]["title"]
    detections: list[dict[str, Any]] = raw["detections"]

    findings: list[Finding] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for det in detections:
        grouped.setdefault(det["rule_id"], []).append(det)
    for rule_id, items in grouped.items():
        rule = by_id.get(rule_id)
        if rule is None:  # rules changed since the run; raw data is still kept
            continue
        items.sort(key=lambda d: d["count"], reverse=True)
        findings.extend(_detection_finding(rule, det) for det in items[:MAX_PER_RULE])
        rest = items[MAX_PER_RULE:]
        if rest:
            findings.append(
                _finding(
                    "log_analyzer.more_sources",
                    category=rule.category,
                    status=FindingStatus.INFO,
                    evidence={
                        "rule_id": rule.id,
                        "sources": [{"key": d["key"], "count": d["count"]} for d in rest[:200]],
                    },
                    more=len(rest),
                    shown=MAX_PER_RULE,
                    rule_title=rule.title,
                )
            )

    period = (
        f"{_when(stats['first_timestamp'])} to {_when(stats['last_timestamp'])}"
        if stats.get("first_timestamp")
        else "an unknown period"
    )
    summary = _finding(
        "log_analyzer.summary",
        category="LOG_SUMMARY",
        status=FindingStatus.INFO,
        evidence={"stats": stats, "parser": raw["parser"]["name"], "rules": raw["rules_evaluated"]},
        lines=f"{stats['lines']:,}",
        parser_title=parser_title,
        detections=len(detections),
        events=f"{stats['events']:,}",
        unrecognised=f"{stats['unrecognised']:,}",
        period=period,
    )
    extra: list[Finding] = [summary]
    nonempty = stats["lines"] - stats.get("empty", 0)
    if nonempty and stats["unrecognised"] / nonempty > UNRECOGNISED_NOTE_RATIO:
        extra.append(
            _finding(
                "log_analyzer.unrecognised_lines",
                category="LOG_FORMAT",
                status=FindingStatus.INFO,
                unrecognised=f"{stats['unrecognised']:,}",
                lines=f"{stats['lines']:,}",
                parser_title=parser_title,
            )
        )
    if not detections:
        extra.append(
            _finding(
                "log_analyzer.no_detections",
                category="LOG_SUMMARY",
                status=FindingStatus.PASS,
                rule_count=len(raw["rules_evaluated"]),
            )
        )
    return sort_by_severity(findings) + extra
