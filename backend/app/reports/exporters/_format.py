"""Formatting helpers shared by the human-readable exporters (PDF, text)."""

import json
from datetime import datetime
from typing import Any

from app.reports.exporters.base import clean_text

EVIDENCE_VALUE_MAX = 400
RAW_SECTION_MAX_CHARS = 30_000
RAW_TOTAL_MAX_CHARS = 120_000
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
COMPACT_WIDTH = 100
NL = "\n"


def fmt_dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def fmt_duration(ms: int | None) -> str:
    if ms is None:
        return "-"
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000
    return f"{seconds:.1f} s" if seconds < 120 else f"{seconds / 60:.1f} min"


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def evidence_lines(evidence: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (clean_text(key), truncate(clean_text(scalar(value)), EVIDENCE_VALUE_MAX))
        for key, value in evidence.items()
    ]


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def compact_json(value: Any, indent: int = 0, width: int = COMPACT_WIDTH) -> str:
    """Indented JSON that keeps short containers on one line.

    ``json.dumps(indent=2)`` puts every list element on its own line, so a
    list of 300 port numbers fills five pages. Here a container whose
    one-line form fits in ``width`` stays on one line.
    """
    flat = _dumps(value)
    if not isinstance(value, dict | list) or len(flat) + indent <= width or not value:
        return flat
    pad, inner = " " * indent, " " * (indent + 2)
    if isinstance(value, dict):
        items = [
            f"{inner}{_dumps(str(k))}: {compact_json(v, indent + 2, width)}"
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        ]
        return NL.join(["{", f",{NL}".join(items), pad + "}"])
    if all(not isinstance(v, dict | list) for v in value):
        # Lists of scalars wrap several per line; nested containers get a line each.
        rows: list[str] = []
        current = ""
        for part in (_dumps(v) for v in value):
            if current and len(inner) + len(current) + len(part) + 2 > width:
                rows.append(inner + current + ",")
                current = part
            else:
                current = f"{current}, {part}" if current else part
        rows.append(inner + current)
        return NL.join(["[", *rows, pad + "]"])
    items = [inner + compact_json(v, indent + 2, width) for v in value]
    return NL.join(["[", f",{NL}".join(items), pad + "]"])


def raw_json(data: dict[str, Any], limit: int = RAW_SECTION_MAX_CHARS) -> tuple[str, bool]:
    """Readable JSON for the appendix, cut at ``limit`` characters. Returns (text, truncated)."""
    text = clean_text(compact_json(data))
    if len(text) <= limit:
        return text, False
    return text[:limit], True
