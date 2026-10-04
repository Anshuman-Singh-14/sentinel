"""Upload storage (04-security.md section 5): random-free naming, caps, atomicity, cleanup."""

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from app.core import uploads
from app.core.errors import PayloadTooLarge, ValidationFailed


async def chunks(*parts: bytes, delay: float = 0) -> AsyncIterator[bytes]:
    for part in parts:
        if delay:
            await asyncio.sleep(delay)
        yield part


async def test_store_streams_to_a_run_named_file(tmp_path: Path) -> None:
    run_id = uuid.uuid4()
    size = await uploads.store(
        tmp_path, run_id, chunks(b"ab", b"cd"), max_bytes=10, timeout_seconds=5
    )
    stored = uploads.path_for(tmp_path, run_id)
    assert size == 4 and stored.read_bytes() == b"abcd"
    assert stored.name == f"{run_id}.upload"  # nothing user-supplied in the path
    if os.name != "nt":
        assert stored.stat().st_mode & 0o777 == 0o600
    assert uploads.exists(tmp_path, run_id)


async def test_over_the_limit_aborts_and_leaves_nothing(tmp_path: Path) -> None:
    run_id = uuid.uuid4()
    with pytest.raises(PayloadTooLarge):
        await uploads.store(
            tmp_path, run_id, chunks(b"x" * 6, b"x" * 6), max_bytes=10, timeout_seconds=5
        )
    assert os.listdir(tmp_path) == []


async def test_slow_upload_times_out(tmp_path: Path) -> None:
    with pytest.raises(ValidationFailed, match="too long"):
        await uploads.store(
            tmp_path,
            uuid.uuid4(),
            chunks(b"a", b"b", b"c", delay=0.05),
            max_bytes=10,
            timeout_seconds=0.06,
        )
    assert os.listdir(tmp_path) == []


async def test_empty_upload_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationFailed, match="empty"):
        await uploads.store(tmp_path, uuid.uuid4(), chunks(), max_bytes=10, timeout_seconds=5)
    assert os.listdir(tmp_path) == []


async def test_an_existing_partial_is_never_overwritten(tmp_path: Path) -> None:
    run_id = uuid.uuid4()
    uploads.path_for(tmp_path, run_id).with_suffix(".part").write_bytes(b"other")
    with pytest.raises(FileExistsError):
        await uploads.store(tmp_path, run_id, chunks(b"a"), max_bytes=10, timeout_seconds=5)


def test_discard_and_sweep(tmp_path: Path) -> None:
    keep, old, gone = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    for run_id in (keep, old, gone):
        uploads.path_for(tmp_path, run_id).write_bytes(b"x")
    (tmp_path / "unrelated.txt").write_bytes(b"x")
    uploads.discard(tmp_path, gone)
    uploads.discard(tmp_path, gone)  # idempotent
    stale = time.time() - 7200
    os.utime(uploads.path_for(tmp_path, old), (stale, stale))

    assert uploads.sweep_stale(tmp_path) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([f"{keep}.upload", "unrelated.txt"])
    assert uploads.sweep_stale(tmp_path / "missing") == 0
