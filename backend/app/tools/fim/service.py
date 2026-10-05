"""Run the scanner in a worker thread while staying cancellable (ADR 0015, section 5).

The walk is blocking filesystem work, so it runs in ``asyncio.to_thread``.
Every 0.5 s the event loop reports progress and checks for cancellation. On
cancellation, the soft time limit (``asyncio.timeout`` cancels this
coroutine) or any error, a stop flag is set that the thread checks between
files and between chunks, so the thread never outlives its run.
"""

import asyncio
import threading
from pathlib import Path

from app.config import Settings
from app.core.errors import Conflict
from app.engine.base_tool import RunCancelled, ToolContext
from app.tools.fim.scanner import (
    ScanLimits,
    ScanProgress,
    ScanResult,
    ScanStopped,
    resolve_base,
    scan,
)

POLL_SECONDS = 0.5
MB = 1024 * 1024


def limits_from(settings: Settings) -> ScanLimits:
    return ScanLimits(
        max_entries=settings.fim_max_files,
        max_file_bytes=settings.fim_max_file_mb * MB,
        max_total_bytes=settings.fim_max_total_mb * MB,
    )


def root_path(settings: Settings, root: str) -> Path:
    try:
        return settings.fim_roots[root]
    except KeyError:
        # The root was removed from FIM_ROOTS after the baseline was made.
        raise Conflict(f"The FIM root {root!r} is no longer configured on the server.") from None


async def scan_directory(
    *,
    root: Path,
    path: str,
    excludes: tuple[str, ...],
    limits: ScanLimits,
    ctx: ToolContext,
    fail_on_limit: bool,
    label: str,
) -> ScanResult:
    base = await asyncio.to_thread(resolve_base, root, path)
    stop = threading.Event()
    progress = ScanProgress()
    worker = asyncio.ensure_future(
        asyncio.to_thread(
            scan,
            base,
            path,
            excludes=excludes,
            limits=limits,
            stop=stop,
            progress=progress,
            fail_on_limit=fail_on_limit,
        )
    )
    # If this coroutine is cancelled first, the thread's ScanStopped is
    # never awaited; retrieve it so asyncio does not log it as unhandled.
    worker.add_done_callback(lambda f: None if f.cancelled() else f.exception())
    try:
        while True:
            done, _ = await asyncio.wait({worker}, timeout=POLL_SECONDS)
            if done:
                break
            # Entry count is the only honest measure: the total is unknown
            # until the walk ends. Cap the bar below 100 until then.
            pct = min(90, 5 + progress.entries * 85 // max(1, limits.max_entries))
            await ctx.report_progress(
                pct, f"{label}: {progress.entries} entries, {progress.bytes_hashed // MB} MB hashed"
            )
            if await ctx.is_cancelled():
                stop.set()
        try:
            return worker.result()
        except ScanStopped:
            raise RunCancelled from None
    finally:
        # Timeout, cancellation or error: tell the thread to stop at its next
        # file or chunk boundary.
        stop.set()
