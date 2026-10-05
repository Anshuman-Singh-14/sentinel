"""Walk a FIM root and record every entry, without following anything (ADR 0015).

Security properties, each covered by a test:

* **No symlink is ever followed.** ``scandir``/``stat`` use
  ``follow_symlinks=False``; a symlink is recorded with its target *text*.
  A link to ``/etc/shadow`` planted in the root is an entry, nothing more.
* **Files are opened with O_NOFOLLOW | O_NONBLOCK**, then checked with
  ``fstat``: the open file must be the same regular file (device and inode)
  that the directory listing saw. A swap in between is noted, not read. A
  FIFO cannot hang the worker, and devices/sockets are never opened at all.
* **Everything is bounded**: entry count, bytes per file, bytes per run,
  directory depth. A ``threading.Event`` stops the walk between files and
  between chunks (cancellation, soft time limit).

This module is synchronous on purpose: it runs in a worker thread
(``asyncio.to_thread``) so slow disks never block the event loop.
"""

import hashlib
import os
import stat
import threading
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from app.core.errors import ValidationFailed
from app.core.security.paths import PathRejected, check_relative_path

CHUNK_BYTES = 1024 * 1024
MAX_LINK_TARGET = 1024
ROOT_ENTRY = "."

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


@dataclass(frozen=True, slots=True)
class Entry:
    """One path's recorded state. ``sha256`` is None when not hashed (see ``note``)."""

    kind: str  # file | dir | symlink | other
    size: int
    mtime_ns: int
    mode: int  # permission and special bits only (S_IMODE)
    uid: int
    gid: int
    sha256: str | None = None
    link_target: str | None = None
    note: str | None = None  # unreadable | too_large | changed_during_scan | too_deep


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_entries: int
    max_file_bytes: int
    max_total_bytes: int
    max_depth: int = 32


@dataclass(slots=True)
class ScanProgress:
    """Written by the scanning thread, read by the event loop (plain ints: safe under the GIL)."""

    entries: int = 0
    bytes_hashed: int = 0
    truncated: bool = False


@dataclass(slots=True)
class ScanResult:
    entries: dict[str, Entry] = field(default_factory=dict)
    truncated: bool = False  # stopped at max_entries (checks only)


class ScanStopped(Exception):  # control flow: cancellation or timeout
    """The stop event was set; the partial result is discarded."""


class TooManyEntries(ValidationFailed):
    code = "fim_too_many_files"
    default_message = "The directory holds too many entries for one baseline."


def resolve_base(root: Path, path: str) -> Path:
    """The directory to scan: ``root/path``, which must be a real directory inside the root.

    Symlinks anywhere in ``path`` are refused (rather than followed and
    contained), so the root-relative names recorded in the baseline are the
    real names on disk.
    """
    try:
        real_root = root.resolve(strict=True)
    except OSError:
        raise PathRejected("This FIM root is not mounted on the worker.") from None
    if not real_root.is_dir():
        raise PathRejected("This FIM root is not a directory.")
    if not path:
        return real_root
    relative = check_relative_path(path)
    candidate = real_root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise PathRejected("No such directory in this FIM root.") from None
    if resolved != candidate:
        raise PathRejected("The path contains a symbolic link, which FIM does not follow.")
    if not resolved.is_dir():
        raise PathRejected("The path is not a directory.")
    return resolved


def is_excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    """Glob match on the root-relative path or the bare name (``*`` also matches ``/``)."""
    name = PurePosixPath(relative).name
    return any(fnmatchcase(relative, p) or fnmatchcase(name, p) for p in patterns)


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"  # FIFO, socket, device: recorded, never opened


def _base_entry(info: os.stat_result, kind: str, **extra: object) -> Entry:
    return Entry(
        kind=kind,
        size=info.st_size if kind == "file" else 0,
        mtime_ns=info.st_mtime_ns,
        mode=stat.S_IMODE(info.st_mode),
        uid=info.st_uid,
        gid=info.st_gid,
        **extra,  # type: ignore[arg-type]
    )


def hash_file(
    path: str, seen: os.stat_result, limit: int, stop: threading.Event
) -> tuple[str | None, str | None, int]:
    """(sha256, note, bytes read). Opens without following links; never blocks on a FIFO."""
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        # ELOOP here means the file became a symlink after it was listed.
        return None, "unreadable", 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (
            seen.st_dev,
            seen.st_ino,
        ):
            return None, "changed_during_scan", 0
        digest = hashlib.sha256()
        read = 0
        while True:
            if stop.is_set():
                raise ScanStopped
            chunk = os.read(fd, CHUNK_BYTES)
            if not chunk:
                break
            read += len(chunk)
            if read > limit:  # the file grew past the cap while being read
                return None, "too_large", read
            digest.update(chunk)
        return digest.hexdigest(), None, read
    except OSError:
        return None, "unreadable", 0
    finally:
        os.close(fd)


def scan(
    base: Path,
    prefix: str,
    *,
    excludes: tuple[str, ...],
    limits: ScanLimits,
    stop: threading.Event,
    progress: ScanProgress,
    fail_on_limit: bool,
) -> ScanResult:
    """Record ``base`` and everything below it. Names are relative to the FIM root.

    ``prefix`` is ``base``'s own root-relative path ("" for the root itself).
    With ``fail_on_limit`` (baselines) too many entries is an error; without
    it (checks) the walk stops and the result is marked truncated.
    """
    result = ScanResult()
    budget = limits.max_total_bytes

    def add(relative: str, entry: Entry) -> bool:
        if len(result.entries) >= limits.max_entries:
            if fail_on_limit:
                raise TooManyEntries(
                    f"More than {limits.max_entries} entries. Choose a subdirectory "
                    "or add exclude patterns."
                )
            result.truncated = progress.truncated = True
            return False
        result.entries[relative] = entry
        progress.entries = len(result.entries)
        return True

    add(prefix or ROOT_ENTRY, _base_entry(base.lstat(), "dir"))
    stack: list[tuple[str, str, int]] = [(str(base), prefix, 0)]
    while stack:
        directory, rel_dir, depth = stack.pop()
        try:
            with os.scandir(directory) as listing:
                children = sorted(listing, key=lambda e: e.name)
        except OSError:
            continue  # unreadable directory: its own entry is already recorded
        for child in children:
            if stop.is_set():
                raise ScanStopped
            relative = f"{rel_dir}/{child.name}" if rel_dir else child.name
            if is_excluded(relative, excludes):
                continue
            try:
                info = child.stat(follow_symlinks=False)
            except OSError:
                continue  # vanished between listing and stat
            kind = _kind(info.st_mode)
            extra: dict[str, object] = {}
            if kind == "symlink":
                try:
                    extra["link_target"] = os.readlink(child.path)[:MAX_LINK_TARGET]
                except OSError:
                    extra["note"] = "unreadable"
            elif kind == "file":
                if info.st_size > limits.max_file_bytes or info.st_size > budget:
                    extra["note"] = "too_large"
                else:
                    digest, note, read = hash_file(child.path, info, limits.max_file_bytes, stop)
                    budget -= read
                    progress.bytes_hashed += read
                    extra["sha256"], extra["note"] = digest, note
            elif kind == "dir" and depth + 1 >= limits.max_depth:
                extra["note"] = "too_deep"
            if not add(relative, _base_entry(info, kind, **extra)):
                return result
            if kind == "dir" and depth + 1 < limits.max_depth:
                stack.append((child.path, relative, depth + 1))
    return result
