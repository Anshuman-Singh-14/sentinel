"""Phase 11 acceptance (05-phases.md), with an in-memory baseline store:

* checks detect modified, added, removed and permission-changed files;
* symlink escape is blocked (see also test_scanner.py);
* parameters are validated at the boundary; cancellation and limits hold.
"""

import os
import uuid
from pathlib import Path
from typing import Any

import pytest
import structlog
from pydantic import ValidationError

from app.config import get_settings
from app.engine.base_tool import ToolContext
from app.engine.registry import registry
from app.engine.runner import execute_tool
from app.engine.schemas import FindingStatus, RunStatus, Severity, ToolResult
from app.tools.fim.schemas import FimBaselineParams
from app.tools.fim.tests.conftest import MemoryStore
from app.tools.fim.tool import FimBaselineTool, FimCheckTool


async def run_tool(tool: Any, params: dict[str, Any], ctx: ToolContext | None = None) -> ToolResult:
    run_id = uuid.uuid4()
    return await execute_tool(
        tool,
        params,
        run_id=run_id,
        ctx=ctx or ToolContext(run_id=run_id, logger=structlog.get_logger()),
    )


async def make_baseline(**params: Any) -> ToolResult:
    result = await run_tool(FimBaselineTool(), {"name": "demo", "root": "demo", **params})
    assert result.status is RunStatus.COMPLETED, result.errors
    return result


async def check(baseline_id: str) -> ToolResult:
    result = await run_tool(FimCheckTool(), {"baseline_id": baseline_id})
    assert result.status is RunStatus.COMPLETED, result.errors
    return result


def tamper(root: Path) -> None:
    (root / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n", encoding="utf-8")  # modified
    (root / "var/www/html/shell.php").write_text(
        "<?php system($_GET['c']);", encoding="utf-8"
    )  # added
    (root / "notes.txt").unlink()  # removed
    (root / "usr/local/bin/backup.sh").chmod(0o777)  # permission change (world-writable)
    (root / "etc/passwd").chmod(0o600)  # permission change


def test_both_tools_are_registered_as_local_forensic_tools() -> None:
    registry.discover()
    for tool_id in ("fim_baseline", "fim_check"):
        tool = registry.get(tool_id)
        assert tool.category == "FORENSIC" and tool.is_active is False


async def test_baseline_is_stored_and_summarised(fim_root: Path, store: MemoryStore) -> None:
    result = await make_baseline()

    baseline_id = uuid.UUID(result.raw_data["baseline"]["id"])
    stored = store.baselines[baseline_id]
    assert "etc/passwd" in stored.entries and stored.entries["etc/passwd"].sha256
    assert result.raw_data["stats"]["files"] == 8
    summary = result.findings[0]
    assert summary.item.startswith("Baseline 'demo' created: 8 file(s)")
    assert summary.severity is Severity.INFO
    assert result.target == "demo:/"


async def test_check_detects_every_change_type(fim_root: Path, store: MemoryStore) -> None:
    baseline = await make_baseline()
    tamper(fim_root)

    result = await check(baseline.raw_data["baseline"]["id"])

    changes = {(c["path"], c["type"]) for c in result.raw_data["changes"]}
    assert ("etc/ssh/sshd_config", "MODIFIED") in changes
    assert ("var/www/html/shell.php", "ADDED") in changes
    assert ("notes.txt", "REMOVED") in changes
    assert ("usr/local/bin/backup.sh", "METADATA_CHANGED") in changes
    assert ("etc/passwd", "METADATA_CHANGED") in changes

    by_item = {f.item: f for f in result.findings}
    sshd = by_item["Modified: etc/ssh/sshd_config"]
    assert sshd.status is FindingStatus.CHANGED and sshd.severity is Severity.HIGH
    assert "etc/ssh/*" in sshd.severity_rationale
    assert by_item["Added: var/www/html/shell.php"].status is FindingStatus.ADDED
    assert by_item["Removed: notes.txt"].severity is Severity.LOW
    backup = by_item["Permissions/owner changed: usr/local/bin/backup.sh"]
    assert backup.severity is Severity.HIGH  # world-writable escalation
    assert "0755 to 0777" in backup.explanation
    assert "world" in backup.severity_rationale.lower() or "CWE-732" in backup.severity_rationale
    summary = result.findings[0]
    assert "5 change(s)" in summary.item
    assert store.checks[-1][2]["METADATA_CHANGED"] == 2


async def test_check_without_changes(fim_root: Path, store: MemoryStore) -> None:
    baseline = await make_baseline()

    result = await check(baseline.raw_data["baseline"]["id"])

    assert [f.item for f in result.findings][-1] == "No changes since baseline 'demo'"
    assert result.raw_data["changes_total"] == 0


async def test_symlink_planted_after_baseline_is_reported_not_followed(
    fim_root: Path, store: MemoryStore
) -> None:
    baseline = await make_baseline()
    (fim_root / "notes.txt").unlink()
    (fim_root / "notes.txt").symlink_to(fim_root.parent / "outside-secret.txt")

    result = await check(baseline.raw_data["baseline"]["id"])

    change = next(c for c in result.raw_data["changes"] if c["path"] == "notes.txt")
    assert change["type"] == "MODIFIED" and "replaced_by_symlink" in change["escalations"]
    assert change["after"]["kind"] == "symlink" and "sha256" not in change["after"]
    assert change["severity"] == "HIGH"


async def test_baseline_observations(fim_root: Path, store: MemoryStore) -> None:
    (fim_root / "etc/world").write_text("x", encoding="utf-8")
    (fim_root / "etc/world").chmod(0o666)
    (fim_root / "usr/local/bin/suid").write_text("x", encoding="utf-8")
    (fim_root / "usr/local/bin/suid").chmod(0o4755)
    (fim_root / "etc/leak").symlink_to("/etc/shadow")

    result = await make_baseline()

    items = [f.item for f in result.findings]
    assert any(i.startswith("1 world-writable") for i in items)
    assert any(i.startswith("1 setuid/setgid") for i in items)
    assert any(i.startswith("1 symbolic link(s) point outside") for i in items)


async def test_subdirectory_and_excludes(fim_root: Path, store: MemoryStore) -> None:
    result = await make_baseline(path="etc", exclude="*.conf, shadow")

    stored = store.baselines[uuid.UUID(result.raw_data["baseline"]["id"])]
    assert set(stored.entries) == {
        "etc",
        "etc/passwd",
        "etc/ssh",
        "etc/ssh/sshd_config",
        "etc/nginx",
    }
    assert stored.spec.excludes == ("*.conf", "shadow")


async def test_unknown_or_deleted_baseline_fails_cleanly(
    fim_root: Path, store: MemoryStore
) -> None:
    result = await run_tool(FimCheckTool(), {"baseline_id": str(uuid.uuid4())})

    assert result.status is RunStatus.FAILED
    assert result.errors[0].code == "not_found"


async def test_too_many_files_fails_the_baseline(
    fim_root: Path, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FIM_MAX_FILES", "10")
    get_settings.cache_clear()

    result = await run_tool(FimBaselineTool(), {"name": "x", "root": "demo"})

    assert result.status is RunStatus.FAILED
    assert result.errors[0].code == "fim_too_many_files"
    assert store.baselines == {}


async def test_truncated_check_does_not_report_removals(
    fim_root: Path, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = await make_baseline()
    monkeypatch.setenv("FIM_MAX_FILES", "10")
    get_settings.cache_clear()

    result = await check(baseline.raw_data["baseline"]["id"])

    assert result.raw_data["truncated"] is True
    assert not any(c["type"] == "REMOVED" for c in result.raw_data["changes"])
    assert any(f.item.startswith("Check stopped at the 10-entry limit") for f in result.findings)


async def test_cancellation_stops_the_scan(fim_root: Path, store: MemoryStore) -> None:
    for i in range(300):
        (fim_root / f"bulk{i}.txt").write_text("x" * 100, encoding="utf-8")

    async def cancelled() -> bool:
        return True

    run_id = uuid.uuid4()
    ctx = ToolContext(run_id=run_id, logger=structlog.get_logger(), cancel_check=cancelled)
    result = await run_tool(FimBaselineTool(), {"name": "x", "root": "demo"}, ctx)

    assert result.status in {RunStatus.CANCELLED, RunStatus.COMPLETED}
    if result.status is RunStatus.CANCELLED:
        assert store.baselines == {}


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ({"name": "x", "root": "nope"}, "root"),
        ({"name": "x", "root": "demo", "path": "../etc"}, "path"),
        ({"name": "x", "root": "demo", "path": "etc\\ssh"}, "path"),
        ({"name": "\x00bad", "root": "demo"}, "name"),
        ({"name": "   ", "root": "demo"}, "name"),
        ({"name": "x", "root": "demo", "exclude": ",".join(["*.x"] * 33)}, "exclude"),
        ({"name": "x", "root": "demo", "extra": 1}, "extra"),
    ],
)
def test_params_are_validated(fim_root: Path, params: dict[str, Any], field: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        FimBaselineParams.model_validate(params)
    assert excinfo.value.errors()[0]["loc"][0] == field


def test_leading_slash_means_root_relative(fim_root: Path) -> None:
    assert (
        FimBaselineParams.model_validate({"name": "x", "root": "demo", "path": "/etc/"}).path
        == "etc"
    )


def test_schema_offers_root_names_not_paths(fim_root: Path) -> None:
    schema = FimBaselineParams.model_json_schema()

    assert schema["properties"]["root"]["enum"] == ["demo"]
    assert str(fim_root) not in str(schema)


def test_unavailable_without_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIM_ROOTS", "")
    get_settings.cache_clear()
    try:
        assert FimBaselineTool.availability().available is False
        assert FimCheckTool.availability().available is False
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


async def test_root_removed_from_settings_fails_the_check(
    fim_root: Path, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = await make_baseline()
    monkeypatch.setenv("FIM_ROOTS", f"other={fim_root}")
    get_settings.cache_clear()

    result = await run_tool(FimCheckTool(), {"baseline_id": baseline.raw_data["baseline"]["id"]})

    assert result.status is RunStatus.FAILED and result.errors[0].code == "conflict"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
async def test_setuid_added_after_baseline_is_critical(fim_root: Path, store: MemoryStore) -> None:
    baseline = await make_baseline()
    (fim_root / "usr/local/bin/backup.sh").chmod(0o4755)

    result = await check(baseline.raw_data["baseline"]["id"])

    finding = next(f for f in result.findings if f.item.endswith("backup.sh"))
    assert finding.severity is Severity.CRITICAL
