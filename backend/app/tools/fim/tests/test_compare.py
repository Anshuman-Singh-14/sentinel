"""Comparison and severity criteria (ADR 0015, section 6)."""

from dataclasses import replace
from pathlib import Path

import pytest

from app.engine.schemas import Severity
from app.tools.fim.compare import ChangeType, Escalation, compare
from app.tools.fim.scanner import Entry
from app.tools.fim.sensitivity import classify, load_rules

FILE = Entry(kind="file", size=4, mtime_ns=1, mode=0o644, uid=0, gid=0, sha256="a" * 64)
DIR = Entry(kind="dir", size=0, mtime_ns=1, mode=0o755, uid=0, gid=0)


def only(baseline: dict[str, Entry], current: dict[str, Entry]):  # type: ignore[no-untyped-def]
    changes, _ = compare(baseline, current)
    assert len(changes) == 1, changes
    return changes[0]


def test_unchanged_and_touched_are_not_reported() -> None:
    touched = replace(FILE, mtime_ns=99)
    changes, stats = compare({"notes.txt": FILE, "d": DIR}, {"notes.txt": touched, "d": DIR})

    assert changes == []
    assert stats.touched == 1 and stats.unchanged == 1


def test_content_change_is_detected_even_with_the_old_mtime() -> None:
    change = only({"notes.txt": FILE}, {"notes.txt": replace(FILE, sha256="b" * 64)})

    assert change.type is ChangeType.MODIFIED and change.details == ("content",)
    assert change.hashed


def test_added_and_removed() -> None:
    changes, stats = compare({"old.txt": FILE}, {"new.txt": FILE})

    assert {(c.path, c.type) for c in changes} == {
        ("old.txt", ChangeType.REMOVED),
        ("new.txt", ChangeType.ADDED),
    }
    assert stats.by_type[ChangeType.ADDED] == stats.by_type[ChangeType.REMOVED] == 1


def test_permission_and_owner_changes_are_metadata_changes() -> None:
    change = only({"notes.txt": FILE}, {"notes.txt": replace(FILE, mode=0o600, uid=1000)})

    assert change.type is ChangeType.METADATA_CHANGED
    assert change.details == ("mode", "owner")


def test_unhashed_files_fall_back_to_size_and_mtime() -> None:
    before = replace(FILE, sha256=None, note="too_large")
    change = only({"big": before}, {"big": replace(before, size=5)})

    assert change.type is ChangeType.MODIFIED and not change.hashed
    assert compare({"big": before}, {"big": before})[0] == []


def test_symlink_target_change_is_a_modification() -> None:
    link = Entry(kind="symlink", size=0, mtime_ns=1, mode=0o777, uid=0, gid=0, link_target="a")
    change = only({"l": link}, {"l": replace(link, link_target="/etc/shadow")})

    assert change.type is ChangeType.MODIFIED and change.details == ("link_target",)


def test_truncated_walks_do_not_report_removals() -> None:
    changes, _ = compare({"a": FILE, "b": FILE}, {"a": FILE}, report_removed=False)

    assert changes == []


@pytest.mark.parametrize(
    ("path", "change_type", "expected"),
    [
        ("etc/shadow", ChangeType.MODIFIED, Severity.CRITICAL),
        ("etc/nginx/nginx.conf", ChangeType.MODIFIED, Severity.HIGH),
        ("var/www/html/shell.php", ChangeType.ADDED, Severity.MEDIUM),
        ("notes.txt", ChangeType.REMOVED, Severity.LOW),
        # metadata-only: one level lower, minimum LOW
        ("etc/shadow", ChangeType.METADATA_CHANGED, Severity.HIGH),
        ("notes.txt", ChangeType.METADATA_CHANGED, Severity.LOW),
    ],
)
def test_severity_follows_path_sensitivity(
    path: str, change_type: ChangeType, expected: Severity
) -> None:
    before = {path: FILE} if change_type is not ChangeType.ADDED else {}
    if change_type is ChangeType.MODIFIED:
        current = {path: replace(FILE, sha256="b" * 64)}
    elif change_type is ChangeType.METADATA_CHANGED:
        current = {path: replace(FILE, mode=0o600)}
    elif change_type is ChangeType.ADDED:
        current = {path: FILE}
    else:
        current = {}

    change = only(before, current)

    assert change.type is change_type and change.severity is expected


def test_world_writable_escalates_to_high() -> None:
    change = only({"notes.txt": FILE}, {"notes.txt": replace(FILE, mode=0o666)})

    assert change.escalations == (Escalation.WORLD_WRITABLE,)
    assert change.severity is Severity.HIGH


def test_sticky_world_writable_directory_is_normal() -> None:
    change = only({"tmp": DIR}, {"tmp": replace(DIR, mode=0o1777)})

    assert change.escalations == () and change.severity is Severity.LOW


def test_new_setuid_bit_is_critical() -> None:
    change = only({"notes.txt": FILE}, {"notes.txt": replace(FILE, mode=0o4755)})
    added = only({}, {"tools/rootshell": replace(FILE, mode=0o4755)})

    assert change.escalations == (Escalation.SETUID,) and change.severity is Severity.CRITICAL
    assert added.severity is Severity.CRITICAL


def test_file_replaced_by_symlink_is_high() -> None:
    link = Entry(kind="symlink", size=0, mtime_ns=1, mode=0o777, uid=0, gid=0, link_target="/x")
    change = only({"notes.txt": FILE}, {"notes.txt": link})

    assert Escalation.REPLACED_BY_SYMLINK in change.escalations
    assert change.severity is Severity.HIGH and "kind" in change.details


def test_changes_are_sorted_most_severe_first() -> None:
    current = {
        "notes.txt": replace(FILE, sha256="b" * 64),
        "etc/shadow": replace(FILE, sha256="b" * 64),
        "etc/passwd": replace(FILE, sha256="b" * 64),
    }
    changes, _ = compare(dict.fromkeys(current, FILE), current)

    assert [c.path for c in changes] == ["etc/shadow", "etc/passwd", "notes.txt"]


def test_sensitivity_rules_file_and_bare_name_patterns(tmp_path: Path) -> None:
    assert classify("home/app/.ssh/authorized_keys").level is Severity.CRITICAL
    assert classify("opt/app/settings.conf").pattern == "*.conf"
    assert classify("README").pattern is None and classify("README").level is Severity.LOW

    custom = tmp_path / "rules.yaml"
    custom.write_text(
        "schema_version: 1\nversion: '1.0.0'\nrules:\n"
        "  - {pattern: 'secret*', level: HIGH, reason: secrets}\n",
        encoding="utf-8",
    )
    rules = load_rules(custom)
    assert classify("deep/dir/secret.env", rules).level is Severity.HIGH  # bare-name match


def test_invalid_rules_file_is_refused(tmp_path: Path) -> None:
    bad = tmp_path / "rules.yaml"
    bad.write_text(
        "schema_version: 1\nversion: '1.0.0'\nrules:\n  - {pattern: x, level: SEVERE, reason: r}\n"
    )
    with pytest.raises(ValueError):
        load_rules(bad)
