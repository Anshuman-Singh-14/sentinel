"""Temporary storage for files uploaded to a tool run (04-security.md section 5, ADR 0014).

The API streams the request body into ``UPLOAD_DIR`` (a volume shared with the
worker); the worker reads it and the framework deletes it when the run ends.

* **The file name is the run id.** Nothing the user sends (file name, path)
  becomes part of a filesystem path, so there is nothing to traverse. A run
  can only ever open the file stored for its own id.
* **Streamed with a hard cap and a deadline.** The body is written in chunks
  and the upload is aborted (and the partial file deleted) as soon as it passes
  the size limit or the time limit. Memory use does not grow with file size.
* **Written atomically.** Data goes to ``<id>.part`` and is renamed to
  ``<id>.upload`` only when complete, so a worker never sees half a file.
* **Owner-only permissions (0600)** and never executed: it is only ever read
  as data.
* **Deleted after processing**, plus an opportunistic sweep of files older
  than an hour, for runs whose worker was killed before it could clean up.
"""

import asyncio
import contextlib
import os
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import BinaryIO

import structlog

from app.core.errors import PayloadTooLarge, ValidationFailed

logger = structlog.get_logger(__name__)

STALE_AFTER_SECONDS = 3600
_SUFFIX = ".upload"


def path_for(upload_dir: Path, run_id: uuid.UUID) -> Path:
    # str(UUID) is canonical hex and dashes only: safe as a file name.
    return upload_dir / f"{run_id}{_SUFFIX}"


async def store(
    upload_dir: Path,
    run_id: uuid.UUID,
    chunks: AsyncIterator[bytes],
    *,
    max_bytes: int,
    timeout_seconds: float,
) -> int:
    """Stream ``chunks`` to the upload file for ``run_id``. Returns the size in bytes."""
    # Disk I/O runs in a worker thread so a slow disk never stalls the API's
    # event loop (and with it every other request).
    final = path_for(upload_dir, run_id)
    partial = final.with_suffix(".part")
    deadline = time.monotonic() + timeout_seconds
    size = 0
    handle = await asyncio.to_thread(_create_exclusive, upload_dir, partial)
    try:
        try:
            async for chunk in chunks:
                size += len(chunk)
                if size > max_bytes:
                    raise PayloadTooLarge(
                        f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit."
                    )
                if time.monotonic() > deadline:
                    raise ValidationFailed("The upload took too long. Try a smaller file.")
                await asyncio.to_thread(handle.write, chunk)
        finally:
            await asyncio.to_thread(handle.close)
        if size == 0:
            raise ValidationFailed("The uploaded file is empty.")
        await asyncio.to_thread(os.replace, partial, final)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            await asyncio.to_thread(partial.unlink)
        raise
    return size


def _create_exclusive(upload_dir: Path, partial: Path) -> BinaryIO:
    """O_EXCL: never reuse or overwrite an existing file. Mode 0600: owner only."""
    upload_dir.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(partial, flags, 0o600), "wb")


def exists(upload_dir: Path, run_id: uuid.UUID) -> bool:
    return path_for(upload_dir, run_id).is_file()


def discard(upload_dir: Path, run_id: uuid.UUID) -> None:
    """Delete the upload for a run (no error if there is none)."""
    for path in (path_for(upload_dir, run_id), path_for(upload_dir, run_id).with_suffix(".part")):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            logger.warning("upload.discard_failed", run_id=str(run_id))


def sweep_stale(upload_dir: Path, *, max_age_seconds: int = STALE_AFTER_SECONDS) -> int:
    """Delete leftovers older than ``max_age_seconds``. Returns how many were removed."""
    if not upload_dir.is_dir():
        return 0
    cutoff = time.time() - max_age_seconds
    removed = 0
    for path in upload_dir.iterdir():
        if path.suffix not in (_SUFFIX, ".part"):
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    if removed:
        logger.info("upload.swept", removed=removed)
    return removed
