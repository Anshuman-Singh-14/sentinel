"""FIM raw output -> educational findings.

Baselines: one summary, plus notes on coverage and on risky permissions that
are already present (better to know before trusting the snapshot).

Checks: one finding per change, most severe first, at most
``MAX_CHANGE_FINDINGS``, plus a grouping finding and an INFO summary. The
severity of a change comes from ``compare.py`` and the rationale names the
sensitivity rule and any escalation, so every rating can be traced.
"""

from datetime import datetime
from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Confidence, Finding, FindingStatus, Severity

MAX_CHANGE_FINDINGS = 200
MAX_EXAMPLES = 5

_STATUS = {
    "MODIFIED": FindingStatus.CHANGED,
    "METADATA_CHANGED": FindingStatus.CHANGED,
    "ADDED": FindingStatus.ADDED,
    "REMOVED": FindingStatus.REMOVED,
}
_KNOWLEDGE = {
    "MODIFIED": "fim.modified",
    "METADATA_CHANGED": "fim.metadata_changed",
    "ADDED": "fim.added",
    "REMOVED": "fim.removed",
}
_ESCALATION_TEXT = {
    "world_writable": "it is now writable by every account on the host (CWE-732): HIGH",
    "setuid": "it now runs with its owner's privileges (setuid/setgid, ATT&CK T1548.001): CRITICAL",
    "replaced_by_symlink": "a regular file was replaced by a symbolic link: HIGH",
}
_NOTE_LABELS = {
    "unreadable": "not readable by the monitor",
    "too_large": "larger than the hashing limit",
    "changed_during_scan": "changed while being read",
    "too_deep": "nested too deeply to descend",
}


def _finding(
    key: str,
    *,
    category: str,
    item: str | None = None,
    status: FindingStatus = FindingStatus.INFO,
    severity: Severity | None = None,
    confidence: Confidence = Confidence.HIGH,
    evidence: dict[str, Any] | None = None,
    values: dict[str, object] | None = None,
) -> Finding:
    entry = get_knowledge_base().get(key)
    values = values or {}
    return Finding(
        item=(item or entry.render("title", **values))[:300],
        category=category,
        status=status,
        severity=severity or entry.severity,
        severity_rationale=entry.render("severity_rationale", **values),
        confidence=confidence,
        explanation=entry.render("explanation", **values),
        remediation=entry.render("remediation", **values),
        evidence=evidence or {},
        references=list(entry.references),
    )


def location(baseline: dict[str, Any]) -> str:
    path = baseline.get("path") or ""
    return f"{baseline['root']}:/{path}"


def _examples(paths: list[str]) -> str:
    shown = ", ".join(paths[:MAX_EXAMPLES])
    return shown + (" and more" if len(paths) > MAX_EXAMPLES else "")


def _when(value: str | None) -> str:
    if not value:
        return "at an unknown time"
    return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M UTC")


# --- baselines -----------------------------------------------------------------------


def translate_baseline(raw: RawOutput) -> list[Finding]:
    baseline: dict[str, Any] = raw["baseline"]
    stats: dict[str, Any] = raw["stats"]
    observations: dict[str, Any] = raw["observations"]
    where = location(baseline)
    findings = [
        _finding(
            "fim.baseline_created",
            category="FIM_BASELINE",
            evidence={"baseline_id": baseline["id"], "location": where, **stats},
            values={
                "name": baseline["name"],
                "files": stats["files"],
                "dirs": stats["dirs"],
                "entries": stats["entries"],
                "location": where,
                "hashed_mb": round(stats["bytes_hashed"] / (1024 * 1024), 1),
            },
        )
    ]

    not_hashed: dict[str, int] = stats.get("not_hashed") or {}
    if sum(not_hashed.values()):
        examples = observations.get("not_hashed") or []
        findings.append(
            _finding(
                "fim.not_hashed",
                category="FIM_COVERAGE",
                evidence={"by_reason": not_hashed, "examples": examples},
                values={
                    "count": sum(not_hashed.values()),
                    "reasons": ", ".join(
                        f"{n} {_NOTE_LABELS.get(k, k)}" for k, n in not_hashed.items() if n
                    ),
                    "examples": _examples(examples),
                },
            )
        )

    for key, field, category, status in (
        ("fim.world_writable_present", "world_writable", "FIM_PERMISSIONS", FindingStatus.WEAK),
        ("fim.setuid_present", "setuid", "FIM_PERMISSIONS", FindingStatus.DETECTED),
        ("fim.external_symlinks", "external_symlinks", "FIM_SYMLINKS", FindingStatus.INFO),
    ):
        paths: list[str] = observations.get(field) or []
        count: int = observations.get(f"{field}_count", len(paths))
        if count:
            findings.append(
                _finding(
                    key,
                    category=category,
                    status=status,
                    evidence={"count": count, "paths": paths},
                    values={"count": count, "examples": _examples(paths)},
                )
            )
    return findings


# --- checks ------------------------------------------------------------------------


def _mode(value: int | None) -> str:
    return f"{value:04o}" if value is not None else "?"


def _describe(change: dict[str, Any]) -> str:
    before, after = change.get("before") or {}, change.get("after") or {}
    parts: list[str] = []
    details = change.get("details") or []
    if "kind" in details:
        parts.append(f"It changed from a {before.get('kind')} to a {after.get('kind')}")
    if "content" in details:
        parts.append(
            "Its content changed (SHA-256 differs)"
            if change.get("hashed", True)
            else "Its size or modification time changed (content could not be hashed)"
        )
    if "link_target" in details:
        parts.append(
            f"The link now points to {after.get('link_target')!r} "
            f"instead of {before.get('link_target')!r}"
        )
    if "mode" in details:
        parts.append(
            f"Its permissions changed from {_mode(before.get('mode'))} "
            f"to {_mode(after.get('mode'))}"
        )
    if "owner" in details:
        parts.append(
            f"Its owner changed from {before.get('uid')}:{before.get('gid')} "
            f"to {after.get('uid')}:{after.get('gid')}"
        )
    return "; ".join(parts) or "It changed"


def _rationale(change: dict[str, Any]) -> str:
    sensitivity = change["sensitivity"]
    if sensitivity.get("pattern"):
        text = (
            f"The path matches sensitivity rule '{sensitivity['pattern']}' "
            f"({sensitivity['level']}: {sensitivity['reason']})."
        )
    else:
        text = f"No sensitivity rule matches this path, so its level is {sensitivity['level']}."
    if change["type"] == "METADATA_CHANGED":
        text += " A permission/owner-only change is rated one level lower (minimum LOW)."
    escalations = change.get("escalations") or []
    if escalations:
        text += " Escalated because " + "; ".join(_ESCALATION_TEXT[e] for e in escalations) + "."
    return text + f" Result: {change['severity']} (criteria in ADR 0015)."


def _change_finding(change: dict[str, Any]) -> Finding:
    entry = change.get("after") or change.get("before") or {}
    escalations = change.get("escalations") or []
    values: dict[str, object] = {
        "path": change["path"],
        "what": _describe(change),
        "reason": change["sensitivity"]["reason"],
        "kind": entry.get("kind", "entry"),
        "rationale": _rationale(change),
        "escalation_text": (
            " Note: " + "; ".join(_ESCALATION_TEXT[e] for e in escalations) + "."
            if escalations
            else ""
        ),
        "confidence_text": (
            ""
            if change.get("hashed", True)
            else "The file could not be hashed, so this is based on size and time only."
        ),
    }
    return _finding(
        _KNOWLEDGE[change["type"]],
        category=f"FIM_{change['type']}",
        status=_STATUS[change["type"]],
        severity=Severity(change["severity"]),
        confidence=Confidence.HIGH if change.get("hashed", True) else Confidence.MEDIUM,
        evidence={
            "path": change["path"],
            "change": change["type"],
            "details": change.get("details") or [],
            "escalations": escalations,
            "sensitivity": change["sensitivity"],
            "before": change.get("before"),
            "after": change.get("after"),
        },
        values=values,
    )


def translate_check(raw: RawOutput) -> list[Finding]:
    baseline: dict[str, Any] = raw["baseline"]
    stats: dict[str, Any] = raw["stats"]
    by_type: dict[str, int] = stats["by_type"]
    changes: list[dict[str, Any]] = raw["changes"]
    total = int(raw.get("changes_total", len(changes)))
    where = location(baseline)
    common = {"name": baseline["name"], "location": where}

    findings = [
        _finding(
            "fim.check_summary",
            category="FIM_SUMMARY",
            evidence={"baseline_id": baseline["id"], "location": where, **stats},
            values={
                **common,
                "current": stats["current_entries"],
                "baseline": stats["baseline_entries"],
                "total": total,
                "created_at": _when(baseline.get("created_at")),
                "created_by": baseline.get("created_by", "unknown"),
                "modified": by_type.get("MODIFIED", 0),
                "added": by_type.get("ADDED", 0),
                "removed": by_type.get("REMOVED", 0),
                "metadata": by_type.get("METADATA_CHANGED", 0),
                "unchanged": stats["unchanged"],
                "touched_text": (
                    f" ({stats['touched']} more had only their timestamp change, which is "
                    "not reported)"
                    if stats.get("touched")
                    else ""
                ),
            },
        )
    ]
    if raw.get("truncated"):
        findings.append(
            _finding(
                "fim.partial", category="FIM_COVERAGE", values={"limit": raw.get("limit", "?")}
            )
        )
    if total == 0:
        findings.append(_finding("fim.no_changes", category="FIM_SUMMARY", values=common))
        return findings

    shown = changes[:MAX_CHANGE_FINDINGS]
    findings.extend(_change_finding(change) for change in shown)
    rest = total - len(shown)
    if rest > 0:
        remaining = changes[len(shown) :]
        highest = remaining[0]["severity"] if remaining else "unknown (beyond the stored list)"
        findings.append(
            _finding(
                "fim.more_changes",
                category="FIM_SUMMARY",
                values={
                    "count": rest,
                    "shown": len(shown),
                    "by_type": ", ".join(f"{n} {t.lower()}" for t, n in by_type.items() if n),
                    "highest": highest,
                },
            )
        )
    return findings
