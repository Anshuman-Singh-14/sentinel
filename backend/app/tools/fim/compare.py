"""Baseline vs. current state: what changed, and how badly (ADR 0015, section 6).

Content is always compared by SHA-256. A matching hash with a different
mtime is only "touched" (backups, ``touch``) and is not reported. A differing
hash is reported even if the attacker reset the mtime. Files that could not
be hashed (unreadable, too large) fall back to size and mtime, with MEDIUM
confidence.
"""

import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from app.engine.schemas import Severity
from app.tools.fim.scanner import Entry
from app.tools.fim.sensitivity import Sensitivity, SensitivityFile, classify

_SPECIAL_BITS = stat.S_ISUID | stat.S_ISGID
_SEVERITY_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


class ChangeType(StrEnum):
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    METADATA_CHANGED = "METADATA_CHANGED"


class Escalation(StrEnum):
    WORLD_WRITABLE = "world_writable"
    SETUID = "setuid"
    REPLACED_BY_SYMLINK = "replaced_by_symlink"


ESCALATION_SEVERITY = {
    Escalation.WORLD_WRITABLE: Severity.HIGH,
    Escalation.SETUID: Severity.CRITICAL,
    Escalation.REPLACED_BY_SYMLINK: Severity.HIGH,
}


@dataclass(frozen=True, slots=True)
class Change:
    path: str
    type: ChangeType
    before: Entry | None
    after: Entry | None
    sensitivity: Sensitivity
    severity: Severity
    details: tuple[str, ...] = ()  # content, kind, link_target, mode, owner
    escalations: tuple[Escalation, ...] = ()
    hashed: bool = True  # False: decided on size/mtime only


@dataclass(slots=True)
class CompareStats:
    baseline_entries: int = 0
    current_entries: int = 0
    unchanged: int = 0
    touched: int = 0  # mtime changed, content identical
    by_type: dict[str, int] = field(default_factory=lambda: dict.fromkeys(ChangeType, 0))


def world_writable(entry: Entry) -> bool:
    """Writable by everyone. Sticky directories (like /tmp) are the normal exception."""
    if entry.kind == "symlink":
        return False  # link permissions are meaningless on Linux
    if entry.kind == "dir" and entry.mode & stat.S_ISVTX:
        return False
    return bool(entry.mode & stat.S_IWOTH)


def special_bits(entry: Entry) -> int:
    return entry.mode & _SPECIAL_BITS if entry.kind == "file" else 0


def _escalations(before: Entry | None, after: Entry | None) -> tuple[Escalation, ...]:
    if after is None:
        return ()
    found: list[Escalation] = []
    if world_writable(after) and not (before is not None and world_writable(before)):
        found.append(Escalation.WORLD_WRITABLE)
    if special_bits(after) & ~(special_bits(before) if before else 0):
        found.append(Escalation.SETUID)
    if before is not None and before.kind == "file" and after.kind == "symlink":
        found.append(Escalation.REPLACED_BY_SYMLINK)
    return tuple(found)


def _lower(level: Severity) -> Severity:
    index = _SEVERITY_ORDER.index(level) if level in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[max(0, index - 1)]


def severity_for(
    change_type: ChangeType, sensitivity: Sensitivity, escalations: tuple[Escalation, ...]
) -> Severity:
    """Path level for content and existence changes, one lower for metadata-only
    changes (minimum LOW); escalations raise it to their own floor."""
    base = sensitivity.level
    if change_type is ChangeType.METADATA_CHANGED:
        base = _lower(base)
    for escalation in escalations:
        floor = ESCALATION_SEVERITY[escalation]
        if floor.rank > base.rank:
            base = floor
    return base


def _differences(before: Entry, after: Entry) -> tuple[list[str], bool]:
    """(what differs, whether content was compared by hash)."""
    details: list[str] = []
    hashed = True
    if before.kind != after.kind:
        details.append("kind")
    elif before.kind == "symlink":
        if before.link_target != after.link_target:
            details.append("link_target")
    elif before.kind == "file":
        if before.sha256 and after.sha256:
            if before.sha256 != after.sha256:
                details.append("content")
        else:
            hashed = False
            if before.size != after.size or before.mtime_ns != after.mtime_ns:
                details.append("content")
    if before.mode != after.mode:
        details.append("mode")
    if (before.uid, before.gid) != (after.uid, after.gid):
        details.append("owner")
    return details, hashed


def compare(
    baseline: Mapping[str, Entry],
    current: Mapping[str, Entry],
    *,
    report_removed: bool = True,
    rules: SensitivityFile | None = None,
) -> tuple[list[Change], CompareStats]:
    """All changes, most severe first (then by path).

    ``report_removed`` is False when the current walk was truncated: an entry
    that was not reached is not proof that it was removed.
    """
    stats = CompareStats(baseline_entries=len(baseline), current_entries=len(current))
    changes: list[Change] = []

    def record(
        path: str,
        change_type: ChangeType,
        before: Entry | None,
        after: Entry | None,
        details: tuple[str, ...] = (),
        hashed: bool = True,
    ) -> None:
        sensitivity = classify(path, rules)
        escalations = _escalations(before, after)
        changes.append(
            Change(
                path=path,
                type=change_type,
                before=before,
                after=after,
                sensitivity=sensitivity,
                severity=severity_for(change_type, sensitivity, escalations),
                details=details,
                escalations=escalations,
                hashed=hashed,
            )
        )
        stats.by_type[change_type] += 1

    for path, after in current.items():
        before = baseline.get(path)
        if before is None:
            record(path, ChangeType.ADDED, None, after)
            continue
        differences, hashed = _differences(before, after)
        if not differences:
            if before.mtime_ns != after.mtime_ns and before.kind == "file":
                stats.touched += 1
            else:
                stats.unchanged += 1
            continue
        content = {"content", "kind", "link_target"} & set(differences)
        record(
            path,
            ChangeType.MODIFIED if content else ChangeType.METADATA_CHANGED,
            before,
            after,
            tuple(differences),
            hashed,
        )

    if report_removed:
        for path, before in baseline.items():
            if path not in current:
                record(path, ChangeType.REMOVED, before, None)

    changes.sort(key=lambda c: (-c.severity.rank, c.path))
    return changes, stats
