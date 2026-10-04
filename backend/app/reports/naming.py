"""Download filenames: built by the server, ASCII-only, never taken from input as is.

The name ends up in a ``Content-Disposition`` header and on the user's disk,
so it must not carry quotes, path separators, control characters or
non-ASCII (header injection, path tricks, mojibake). Target names come from
users and DNS, so they are reduced to a safe slug.
"""

import re
import unicodedata
from datetime import datetime

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
SLUG_MAX = 40


def slug(value: str | None, limit: int = SLUG_MAX) -> str:
    ascii_text = (
        unicodedata.normalize("NFKD", value or "").encode("ascii", "ignore").decode("ascii")
    )
    return _UNSAFE.sub("-", ascii_text).strip("-._")[:limit].strip("-._")


def report_filename(
    *, kind: str, name: str, target: str | None, created_at: datetime, extension: str
) -> str:
    parts = [
        "sentinel",
        "playbook" if kind == "playbook_run" else "run",
        slug(name) or "report",
        slug(target),
        created_at.strftime("%Y%m%d-%H%M%S"),
    ]
    return "-".join(p for p in parts if p) + "." + (slug(extension, 8) or "bin")
