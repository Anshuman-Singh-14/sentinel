"""Read -> parse -> detect, in one streaming pass.

The analysis is CPU-bound, so it yields to the event loop every
``YIELD_EVERY`` lines. That is what lets the framework's soft time limit
(``asyncio.timeout``) and cooperative cancellation actually interrupt a long
run, and it is where progress is reported.
"""

import asyncio
import itertools
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from app.core.errors import NotFound, ValidationFailed
from app.core.security.paths import PathGuard
from app.engine.base_tool import RawOutput, ToolContext
from app.tools.log_analyzer import parsers
from app.tools.log_analyzer.reader import ReadStats, iter_lines, open_stream
from app.tools.log_analyzer.rules import Detection, RuleFile, detectors_for

YIELD_EVERY = 5000


class UnsupportedLog(ValidationFailed):
    code = "unsupported_log_format"
    default_message = "Sentinel does not recognise this log format."


def open_source(
    *, path: str, upload_path: Path | None, log_root: Path | None
) -> tuple[BinaryIO, int | None, str]:
    """Open the input. Returns (binary stream, size, display name)."""
    if path:
        if log_root is None:
            raise NotFound("Reading server logs is disabled (LOG_ROOT is not set).")
        guard = PathGuard([log_root])
        guarded = guard.resolve(path)
        return guard.open(guarded), guarded.size, guarded.relative
    if upload_path is None or not upload_path.is_file():
        raise NotFound("The uploaded file for this run is no longer available.")
    return open(upload_path, "rb"), upload_path.stat().st_size, ""  # closed by the caller


def _detection_dict(item: Detection) -> dict[str, Any]:
    return {
        "rule_id": item.rule.id,
        "key": item.key,
        "count": item.count,
        "first_seen": item.first_seen.isoformat() if item.first_seen else None,
        "last_seen": item.last_seen.isoformat() if item.last_seen else None,
        "details": item.details,
    }


async def analyse(
    stream: BinaryIO,
    *,
    size: int | None,
    parser_choice: str,
    rules: RuleFile,
    ctx: ToolContext,
    max_lines: int,
    max_line_bytes: int,
    max_total_bytes: int,
    reference: datetime | None = None,
) -> RawOutput:
    reference = reference or datetime.now(UTC)
    stats = ReadStats()
    lines: Iterator[str] = iter_lines(
        open_stream(stream, stats),
        stats,
        max_lines=max_lines,
        max_line_bytes=max_line_bytes,
        max_total_bytes=max_total_bytes,
    )

    if parser_choice == "auto":
        sample = list(itertools.islice(lines, parsers.DETECT_SAMPLE_LINES))
        chosen = parsers.detect(sample, reference)
        if chosen is None:
            raise UnsupportedLog(
                "Sentinel could not recognise this log. Supported formats: SSH auth.log "
                "(OpenSSH via syslog) and nginx/Apache access logs in the combined format."
            )
        lines = itertools.chain(sample, lines)
    else:
        chosen = parser_choice

    parser = parsers.build(chosen, reference)
    detectors = detectors_for(chosen, rules)
    counts = {"recognised": 0, "events": 0, "unrecognised": 0, "empty": 0}
    events_by_kind: dict[str, int] = {}
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    await ctx.report_progress(1, f"Reading as {parser.title}")
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            counts["empty"] += 1
        else:
            result = parser.parse(line, line_no)
            if not result.recognised:
                counts["unrecognised"] += 1
            else:
                counts["recognised"] += 1
            event = result.event
            if event is not None:
                counts["events"] += 1
                events_by_kind[event.kind] = events_by_kind.get(event.kind, 0) + 1
                if event.timestamp is not None:
                    first_ts = (
                        event.timestamp if first_ts is None else min(first_ts, event.timestamp)
                    )
                    last_ts = event.timestamp if last_ts is None else max(last_ts, event.timestamp)
                for detector in detectors:
                    if detector.wants(event):
                        detector.feed(event)
        if line_no % YIELD_EVERY == 0:
            await ctx.raise_if_cancelled()
            pct = min(95, int(stats.bytes_read * 95 / size)) if size else 50
            await ctx.report_progress(max(pct, 2), f"{line_no:,} lines read")
            await asyncio.sleep(0)

    detections: list[Detection] = []
    partial_rules: list[str] = []
    for detector in detectors:
        detections.extend(detector.results())
        if detector.overflow:
            partial_rules.append(detector.rule.id)
    if stats.stopped_early:
        ctx.add_error("log_truncated", f"Analysis stopped early: {stats.stopped_early}.")
    if partial_rules:
        ctx.add_error(
            "too_many_sources",
            "Too many distinct source addresses to track them all; results for "
            + ", ".join(partial_rules)
            + " are partial.",
        )
    await ctx.report_progress(100, "Done")
    return {
        "parser": parser.describe(),
        "parser_choice": parser_choice,
        "rules_version": rules.version,
        "rules_evaluated": [d.rule.id for d in detectors],
        "stats": {
            "lines": stats.lines,
            "bytes_read": stats.bytes_read,
            "compressed": stats.compressed,
            "truncated_lines": stats.truncated_lines,
            "stopped_early": stats.stopped_early,
            **counts,
            "events_by_kind": events_by_kind,
            "first_timestamp": first_ts.isoformat() if first_ts else None,
            "last_timestamp": last_ts.isoformat() if last_ts else None,
        },
        "detections": [_detection_dict(d) for d in detections],
    }
