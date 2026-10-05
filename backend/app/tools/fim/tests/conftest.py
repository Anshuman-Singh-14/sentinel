"""Shared fixtures: a FIM root in a temp directory and an in-memory baseline store."""

import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.config import get_settings
from app.tools.fim import tool as fim_tool
from app.tools.fim.scanner import Entry
from app.tools.fim.store import BaselineNotFound, BaselineSpec, SavedBaseline, StoredBaseline


class MemoryStore:
    def __init__(self) -> None:
        self.baselines: dict[uuid.UUID, StoredBaseline] = {}
        self.checks: list[tuple[uuid.UUID, uuid.UUID, dict[str, int]]] = []

    async def save(
        self, run_id: uuid.UUID, spec: BaselineSpec, entries: Mapping[str, Entry]
    ) -> SavedBaseline:
        baseline_id = uuid.uuid4()
        now = datetime.now(UTC)
        self.baselines[baseline_id] = StoredBaseline(baseline_id, spec, now, "ana", dict(entries))
        return SavedBaseline(baseline_id, now, "ana")

    async def load(self, baseline_id: uuid.UUID) -> StoredBaseline:
        try:
            return self.baselines[baseline_id]
        except KeyError:
            raise BaselineNotFound(str(baseline_id)) from None

    async def record_check(
        self, run_id: uuid.UUID, baseline_id: uuid.UUID, counts: Mapping[str, int]
    ) -> None:
        self.checks.append((run_id, baseline_id, dict(counts)))


def build_tree(root: Path) -> None:
    """A miniature filesystem like the lab-fim demo volume."""
    files = {
        "etc/passwd": (
            "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n",
            0o644,
        ),
        "etc/shadow": ("root:!:19000::::::\n", 0o640),
        "etc/ssh/sshd_config": ("PermitRootLogin no\nPasswordAuthentication no\n", 0o644),
        "etc/nginx/nginx.conf": ("server { listen 80; }\n", 0o644),
        "usr/local/bin/backup.sh": ("#!/bin/sh\necho backup\n", 0o755),
        "var/www/html/index.html": ("<h1>hello</h1>\n", 0o644),
        "home/app/.ssh/authorized_keys": ("ssh-ed25519 AAAA demo@laptop\n", 0o600),
        "notes.txt": ("todo\n", 0o644),
    }
    for relative, (content, mode) in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)


@pytest.fixture
def fim_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "root"
    root.mkdir()
    build_tree(root)
    (tmp_path / "outside-secret.txt").write_text("never read me", encoding="utf-8")
    monkeypatch.setenv("FIM_ROOTS", f"demo={root}")
    get_settings.cache_clear()
    yield root
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> MemoryStore:
    memory = MemoryStore()
    monkeypatch.setattr(fim_tool, "store_factory", lambda: memory)
    return memory
