"""Scanner: what is recorded, what is never followed, and every limit (ADR 0015, section 5)."""

import hashlib
import os
import threading
from pathlib import Path

import pytest

from app.core.security.paths import PathRejected
from app.tools.fim.scanner import (
    ROOT_ENTRY,
    ScanLimits,
    ScanProgress,
    ScanResult,
    ScanStopped,
    TooManyEntries,
    hash_file,
    is_excluded,
    resolve_base,
    scan,
)

LIMITS = ScanLimits(max_entries=1000, max_file_bytes=10**6, max_total_bytes=10**7)


def run_scan(
    base: Path,
    prefix: str = "",
    *,
    excludes: tuple[str, ...] = (),
    limits: ScanLimits = LIMITS,
    fail_on_limit: bool = True,
    stop: threading.Event | None = None,
) -> ScanResult:
    return scan(
        base,
        prefix,
        excludes=excludes,
        limits=limits,
        stop=stop or threading.Event(),
        progress=ScanProgress(),
        fail_on_limit=fail_on_limit,
    )


def test_records_files_dirs_hashes_and_modes(fim_root: Path) -> None:
    entries = run_scan(fim_root).entries

    assert entries[ROOT_ENTRY].kind == "dir"
    passwd = entries["etc/passwd"]
    content = (fim_root / "etc/passwd").read_bytes()
    assert passwd.kind == "file" and passwd.size == len(content)
    assert passwd.sha256 == hashlib.sha256(content).hexdigest()
    assert passwd.mode == 0o644 and passwd.uid == os.getuid()
    assert entries["usr/local/bin/backup.sh"].mode == 0o755
    assert entries["etc/ssh"].kind == "dir"


def test_subdirectory_names_stay_root_relative(fim_root: Path) -> None:
    entries = run_scan(fim_root / "etc", "etc").entries

    assert "etc" in entries and "etc/ssh/sshd_config" in entries
    assert not any(p.startswith("var/") for p in entries)


def test_symlink_to_a_file_outside_is_recorded_not_read(fim_root: Path) -> None:
    outside = fim_root.parent / "outside-secret.txt"
    (fim_root / "etc" / "leak").symlink_to(outside)

    entry = run_scan(fim_root).entries["etc/leak"]

    assert entry.kind == "symlink"
    assert entry.link_target == str(outside)
    assert entry.sha256 is None  # the target's content was never opened


def test_symlinked_directory_outside_is_not_descended(fim_root: Path) -> None:
    outside = fim_root.parent / "outside-dir"
    outside.mkdir()
    (outside / "private.key").write_text("secret", encoding="utf-8")
    (fim_root / "escape").symlink_to(outside, target_is_directory=True)

    entries = run_scan(fim_root).entries

    assert entries["escape"].kind == "symlink"
    assert not any(p.startswith("escape/") for p in entries)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_fifo_is_recorded_and_never_opened(fim_root: Path) -> None:
    os.mkfifo(fim_root / "trap")  # opening this for reading would block forever

    entry = run_scan(fim_root).entries["trap"]

    assert entry.kind == "other" and entry.sha256 is None


def test_hash_refuses_a_file_swapped_after_listing(fim_root: Path) -> None:
    target = fim_root / "notes.txt"
    seen = (fim_root / "etc/passwd").lstat()  # a different inode

    digest, note, _ = hash_file(str(target), seen, 10**6, threading.Event())

    assert digest is None and note == "changed_during_scan"


def test_hash_refuses_a_file_replaced_by_a_symlink(fim_root: Path) -> None:
    target = fim_root / "notes.txt"
    seen = target.lstat()
    target.unlink()
    target.symlink_to(fim_root.parent / "outside-secret.txt")

    digest, note, _ = hash_file(str(target), seen, 10**6, threading.Event())

    assert digest is None and note == "unreadable"  # O_NOFOLLOW refused it


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="root reads everything")
def test_unreadable_file_keeps_its_metadata(fim_root: Path) -> None:
    secret = fim_root / "etc" / "shadow"
    secret.chmod(0o000)
    try:
        entry = run_scan(fim_root).entries["etc/shadow"]
    finally:
        secret.chmod(0o640)
    assert entry.sha256 is None and entry.note == "unreadable" and entry.mode == 0


def test_excludes_match_path_or_name(fim_root: Path) -> None:
    entries = run_scan(fim_root, excludes=("*.txt", "nginx")).entries

    assert "notes.txt" not in entries
    assert "etc/nginx" not in entries and "etc/nginx/nginx.conf" not in entries
    assert "etc/passwd" in entries
    assert is_excluded("var/log/app.log", ("*.log",))
    assert not is_excluded("var/log/app.log.1", ("*.log",))


def test_too_many_entries_fails_a_baseline(fim_root: Path) -> None:
    with pytest.raises(TooManyEntries):
        run_scan(fim_root, limits=ScanLimits(5, 10**6, 10**7))


def test_too_many_entries_truncates_a_check(fim_root: Path) -> None:
    result = run_scan(fim_root, limits=ScanLimits(5, 10**6, 10**7), fail_on_limit=False)

    assert result.truncated and len(result.entries) == 5


def test_large_files_keep_metadata_only(fim_root: Path) -> None:
    (fim_root / "big.bin").write_bytes(b"x" * 5000)

    entries = run_scan(fim_root, limits=ScanLimits(1000, 4096, 10**7)).entries

    assert entries["big.bin"].sha256 is None and entries["big.bin"].note == "too_large"
    assert entries["big.bin"].size == 5000


def test_total_hash_budget(fim_root: Path) -> None:
    entries = run_scan(fim_root, limits=ScanLimits(1000, 10**6, 60)).entries

    notes = [e.note for e in entries.values() if e.kind == "file"]
    assert "too_large" in notes and None in notes  # early files hashed, later ones not


def test_depth_limit(fim_root: Path) -> None:
    deep = fim_root / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "x").write_text("x", encoding="utf-8")

    entries = run_scan(fim_root, limits=ScanLimits(1000, 10**6, 10**7, max_depth=2)).entries

    assert entries["a/b"].note == "too_deep"
    assert "a/b/c" not in entries


def test_stop_event_aborts(fim_root: Path) -> None:
    stop = threading.Event()
    stop.set()
    with pytest.raises(ScanStopped):
        run_scan(fim_root, stop=stop)


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("../outside-secret.txt", "'..'"),
        ("/etc", "absolute"),
        ("missing", "No such directory"),
        ("notes.txt", "not a directory"),
    ],
)
def test_resolve_base_rejects(fim_root: Path, path: str, message: str) -> None:
    with pytest.raises(PathRejected, match=message):
        resolve_base(fim_root, path)


def test_resolve_base_rejects_symlinked_components(fim_root: Path) -> None:
    (fim_root / "shortcut").symlink_to(fim_root / "etc", target_is_directory=True)
    (fim_root / "out").symlink_to(fim_root.parent, target_is_directory=True)

    with pytest.raises(PathRejected, match="symbolic link"):
        resolve_base(fim_root, "shortcut")
    with pytest.raises(PathRejected):
        resolve_base(fim_root, "out")


def test_resolve_base_requires_a_mounted_root(tmp_path: Path) -> None:
    with pytest.raises(PathRejected, match="not mounted"):
        resolve_base(tmp_path / "nope", "")
    assert resolve_base(tmp_path, "") == tmp_path.resolve()
