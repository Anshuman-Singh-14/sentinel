"""Path traversal protection (04-security.md section 5).

Every file a user names is opened through ``PathGuard``. A user path is
treated as untrusted text that must end up *inside* one of the allowed roots:

1. Reject null bytes, absolute paths, drive letters and backslashes before
   touching the filesystem. Those are never legitimate in a "file inside
   LOG_ROOT" field, and rejecting them early gives a clear message.
2. Resolve the joined path strictly (``resolve(strict=True)``): symlinks are
   followed and ``..`` collapsed, and a missing file is an error.
3. Require the resolved path to be inside the resolved root. This is what
   stops ``../../etc/passwd``, URL-decoded variants that reached us decoded,
   and symlinks that point out of the root.
4. Open with ``O_NOFOLLOW`` (where the OS has it) and check, on the open file
   descriptor, that it is still a regular file inside the root. This narrows
   the time-of-check/time-of-use window: a file swapped for a symlink between
   steps 2 and 4 is refused rather than followed.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from app.core.errors import NotFound, ValidationFailed

MAX_PATH_LENGTH = 255


class PathRejected(ValidationFailed):
    code = "path_rejected"
    default_message = "That path is not allowed."


@dataclass(frozen=True, slots=True)
class GuardedFile:
    path: Path  # resolved, inside the root
    relative: str  # as shown to users (never the absolute server path)
    size: int


def check_relative_path(user_path: str) -> str:
    """Syntactic checks only (no filesystem access). Returns the normalised text.

    Used by Pydantic validators at the API boundary for fast, clear errors;
    ``PathGuard.resolve`` repeats them and adds the filesystem checks.
    """
    if not user_path or len(user_path) > MAX_PATH_LENGTH:
        raise PathRejected(f"Give a file name of 1-{MAX_PATH_LENGTH} characters.")
    if "\x00" in user_path:
        raise PathRejected("The path contains a null byte.")
    if "\\" in user_path:
        raise PathRejected("Use forward slashes in paths.")
    if user_path.startswith("/") or (len(user_path) > 1 and user_path[1] == ":"):
        raise PathRejected("Give a path relative to the log directory, not an absolute path.")
    parts = PurePosixPath(user_path).parts
    if any(part == ".." for part in parts):
        raise PathRejected("The path may not contain '..'.")
    if any(ord(ch) < 32 for ch in user_path):
        raise PathRejected("The path contains control characters.")
    return str(PurePosixPath(*parts))


class PathGuard:
    """Resolve and open user-named files inside a fixed set of allowed roots."""

    def __init__(self, roots: list[Path]) -> None:
        # Resolve roots once; a root that does not exist is simply unusable.
        self.roots = [root.resolve() for root in roots if root.is_dir()]

    def resolve(self, user_path: str) -> GuardedFile:
        relative = check_relative_path(user_path)
        for root in self.roots:
            candidate = root / relative
            try:
                resolved = candidate.resolve(strict=True)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except (OSError, RuntimeError):  # symlink loop, permission denied
                raise PathRejected("That path cannot be opened.") from None
            if not resolved.is_relative_to(root):
                # A symlink (or anything else) that leaves the root.
                raise PathRejected("That path points outside the allowed directory.")
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                raise PathRejected("That path is not a regular file.")
            return GuardedFile(path=resolved, relative=relative, size=info.st_size)
        raise NotFound("No such file in the log directory.")

    def open(self, guarded: GuardedFile) -> BinaryIO:
        """Open a resolved file without following a last-moment symlink swap."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(guarded.path, flags)
        except OSError:
            raise PathRejected("That path cannot be opened.") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise PathRejected("That path is not a regular file.")
            # Re-check containment on the final path (the swap could have
            # replaced a parent directory with a symlink).
            real = Path(os.path.realpath(guarded.path))
            if not any(real.is_relative_to(root) for root in self.roots):
                raise PathRejected("That path points outside the allowed directory.")
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
