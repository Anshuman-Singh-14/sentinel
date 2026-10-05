"""File Integrity Monitor end to end on real Postgres and Redis (Phase 11, ADR 0015).

Run endpoints -> Celery task body -> baseline rows and audit events ->
check findings, plus baseline management (schedule, delete, ownership),
scheduled dispatch, database grants and the Phase 13 exporters (ADR 0009
checklist).
"""

import csv
import io
import uuid
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import ProgrammingError

from app.config import get_settings
from app.core.auth.roles import Role
from app.core.runs import events
from app.core.runs.dispatch import get_dispatcher
from app.core.tasks import loop
from app.core.tasks.tool_task import run_tool
from app.db import session as db_session
from app.db.models._types import utcnow
from app.fim.schedule import dispatch_due
from app.reports.dispatch import get_report_dispatcher
from app.reports.generate import generate_report
from app.tools.fim.tests.conftest import build_tree
from tests.integration.conftest import (
    Database,
    csrf,
    login,
    restore_cookies,
    save_cookies,
)


class Captured:
    def __init__(self) -> None:
        self.sent: list[uuid.UUID] = []

    def send(self, item_id: uuid.UUID, *_: Any) -> str:
        self.sent.append(item_id)
        return f"task-{item_id}"

    def revoke(self, task_id: str) -> None:
        return None


@pytest.fixture
def fim_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "root"
    root.mkdir()
    build_tree(root)
    monkeypatch.setenv("FIM_ROOTS", f"demo={root}")
    get_settings.cache_clear()
    yield root
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def analyst(
    app: FastAPI, client: TestClient, make_user: Callable[..., Any], fim_root: Path
) -> Iterator[Any]:
    for dependency in (get_dispatcher, get_report_dispatcher):
        app.dependency_overrides[dependency] = Captured
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    yield user_id
    for dependency in (get_dispatcher, get_report_dispatcher):
        app.dependency_overrides.pop(dependency, None)


def in_worker[T](fn: Callable[[], T]) -> T:
    """Run worker-side code with its own engine and Redis client, as a Celery worker would."""
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()
    try:
        result = fn()
        loop.run_async(db_session.dispose_engine())
        loop.run_async(events.close_redis())
        return result
    finally:
        loop.reset_loop()
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


def start(client: TestClient, tool_id: str, params: dict[str, Any]) -> str:
    response = client.post(
        f"/api/v1/tools/{tool_id}/runs", json={"params": params}, headers=csrf(client)
    )
    assert response.status_code == 202, response.text
    run_id: str = response.json()["run_id"]
    assert in_worker(lambda: run_tool.run(run_id)) == "COMPLETED"
    return run_id


def create_baseline(client: TestClient, name: str = "demo") -> str:
    run_id = start(client, "fim_baseline", {"name": name, "root": "demo"})
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    baseline_id: str = detail["raw_data"]["baseline"]["id"]
    return baseline_id


def _report_job(report_id: uuid.UUID) -> Callable[[], str]:
    return lambda: loop.run_async(generate_report(report_id))


def test_catalogue_offers_root_names(client: TestClient, analyst: Any, fim_root: Path) -> None:
    tools = {t["tool_id"]: t for t in client.get("/api/v1/tools").json()}

    baseline = tools["fim_baseline"]
    assert baseline["available"] is True and baseline["category"] == "FORENSIC"
    assert baseline["params_schema"]["properties"]["root"]["enum"] == ["demo"]
    assert baseline["status"] == {"roots": ["demo"]}
    assert str(fim_root) not in str(tools)  # server paths never reach the browser
    assert tools["fim_check"]["is_active"] is False


def test_baseline_then_check_end_to_end(
    client: TestClient, db: Database, analyst: Any, fim_root: Path
) -> None:
    baseline_id = create_baseline(client)

    (row,) = db.execute("SELECT * FROM fim_baselines")
    assert str(row["id"]) == baseline_id
    assert row["created_by"] == analyst and row["created_by_username"] == "ana"
    assert row["file_count"] == 8 and row["root"] == "demo"
    entries = db.execute(
        "SELECT path, sha256, mode FROM fim_baseline_entries WHERE baseline_id = :b",
        {"b": baseline_id},
    )
    by_path = {e["path"]: e for e in entries}
    assert by_path["etc/passwd"]["sha256"] and by_path["etc/passwd"]["mode"] == 0o644
    (created,) = db.audit("fim.baseline.created")
    assert created["username"] == "ana" and created["resource_id"] == baseline_id
    assert created["target"] == "demo:/"

    (fim_root / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n", encoding="utf-8")
    (fim_root / "var/www/html/shell.php").write_text("<?php", encoding="utf-8")
    (fim_root / "notes.txt").unlink()
    (fim_root / "etc/passwd").chmod(0o666)

    check_id = start(client, "fim_check", {"baseline_id": baseline_id})

    detail = client.get(f"/api/v1/runs/{check_id}").json()
    items = {f["item"]: f for f in detail["findings"]}
    assert items["Modified: etc/ssh/sshd_config"]["severity"] == "HIGH"
    assert items["Added: var/www/html/shell.php"]["status"] == "ADDED"
    assert items["Removed: notes.txt"]["status"] == "REMOVED"
    assert items["Permissions/owner changed: etc/passwd"]["severity"] == "HIGH"
    (checked,) = db.audit("fim.check.completed")
    assert checked["details"]["changes"] == 4 and checked["username"] == "ana"
    (row,) = db.execute("SELECT last_check_run_id, last_check_changes FROM fim_baselines")
    assert str(row["last_check_run_id"]) == check_id and row["last_check_changes"] == 4

    listed = client.get("/api/v1/fim/baselines").json()
    assert listed["schedule_choices"] == [15, 60, 360, 1440]
    assert listed["baselines"][0]["last_check_changes"] == 4

    # Phase 13 exporters render FIM findings unchanged (ADR 0009 checklist).
    for fmt in ("pdf", "csv"):
        report_id = client.post(
            "/api/v1/reports",
            json={"source_type": "tool_run", "source_id": check_id, "format": fmt},
            headers=csrf(client),
        ).json()["report_id"]
        assert in_worker(_report_job(uuid.UUID(report_id))) == "COMPLETED"
        content = client.get(f"/api/v1/reports/{report_id}/download").content
        if fmt == "pdf":
            assert content.startswith(b"%PDF-")
        else:
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
            assert any("etc/ssh/sshd_config" in r["item"] for r in rows)


def test_schedule_and_delete_are_owner_or_admin_only(
    client: TestClient, db: Database, analyst: Any, make_user: Callable[..., Any]
) -> None:
    baseline_id = create_baseline(client)
    ana = save_cookies(client)
    url = f"/api/v1/fim/baselines/{baseline_id}"

    make_user("bob", Role.ANALYST)
    login(client, "bob")
    assert client.patch(url, json={"schedule_minutes": 60}, headers=csrf(client)).status_code == 403
    assert client.delete(url, headers=csrf(client)).status_code == 403
    denied = db.audit("auth.access.denied")
    assert denied[-1]["reason"] == "not_baseline_owner"

    restore_cookies(client, ana)
    bad = client.patch(url, json={"schedule_minutes": 7}, headers=csrf(client))
    assert bad.status_code == 422
    ok = client.patch(url, json={"schedule_minutes": 60}, headers=csrf(client))
    assert ok.status_code == 200 and ok.json()["schedule_minutes"] == 60
    (updated,) = db.audit("fim.baseline.updated")
    assert updated["details"]["schedule_minutes"] == {"from": None, "to": 60}

    make_user("root", Role.ADMIN)
    login(client, "root")
    assert client.delete(url, headers=csrf(client)).status_code == 204
    (row,) = db.execute("SELECT deleted_at, deleted_by, schedule_minutes FROM fim_baselines")
    assert row["deleted_at"] is not None and row["schedule_minutes"] is None
    count = db.execute("SELECT count(*) AS n FROM fim_baseline_entries")[0]["n"]
    assert count == 0
    assert len(db.audit("fim.baseline.deleted")) == 1
    assert client.get("/api/v1/fim/baselines").json()["baselines"] == []

    # A check against a deleted baseline fails cleanly.
    restore_cookies(client, ana)
    response = client.post(
        "/api/v1/tools/fim_check/runs",
        json={"params": {"baseline_id": baseline_id}},
        headers=csrf(client),
    )
    run_id = response.json()["run_id"]
    assert in_worker(lambda: run_tool.run(run_id)) == "FAILED"
    assert client.get(f"/api/v1/runs/{run_id}").json()["errors"][0]["code"] == "not_found"


def test_viewers_can_list_but_not_change(
    client: TestClient, analyst: Any, make_user: Callable[..., Any]
) -> None:
    baseline_id = create_baseline(client)
    make_user("vic", Role.VIEWER)
    login(client, "vic")

    assert client.get("/api/v1/fim/baselines").status_code == 200
    url = f"/api/v1/fim/baselines/{baseline_id}"
    assert client.patch(url, json={"schedule_minutes": 15}, headers=csrf(client)).status_code == 403
    assert (
        client.post(
            "/api/v1/tools/fim_baseline/runs",
            json={"params": {"name": "x", "root": "demo"}},
            headers=csrf(client),
        ).status_code
        == 403
    )


def test_scheduled_dispatch(
    client: TestClient, db: Database, analyst: Any, make_user: Callable[..., Any]
) -> None:
    baseline_id = create_baseline(client)
    client.patch(
        f"/api/v1/fim/baselines/{baseline_id}",
        json={"schedule_minutes": 15},
        headers=csrf(client),
    )
    captured = Captured()

    # Not due yet: the first check is one interval after the schedule is set.
    assert in_worker(lambda: loop.run_async(dispatch_due(dispatcher=captured))) == []

    later = utcnow() + timedelta(minutes=16)
    started = in_worker(lambda: loop.run_async(dispatch_due(later, dispatcher=captured)))
    assert len(started) == 1 and captured.sent == started
    (run_row,) = db.execute("SELECT * FROM tool_runs WHERE id = :id", {"id": started[0]})
    assert run_row["tool_id"] == "fim_check" and run_row["user_id"] == analyst
    requested = [r for r in db.audit("tool.run.requested") if r["resource_id"] == str(started[0])]
    assert requested[0]["details"]["trigger"] == "schedule"

    # Claimed: the same tick again starts nothing.
    assert in_worker(lambda: loop.run_async(dispatch_due(later, dispatcher=captured))) == []

    # A disabled creator's schedule is cleared instead of run in their name.
    db.execute("UPDATE users SET is_active = false WHERE id = :id", {"id": analyst})
    much_later = later + timedelta(minutes=16)
    assert in_worker(lambda: loop.run_async(dispatch_due(much_later, dispatcher=captured))) == []
    (row,) = db.execute("SELECT schedule_minutes FROM fim_baselines")
    assert row["schedule_minutes"] is None


def test_app_role_cannot_delete_baseline_rows(
    client: TestClient, db: Database, analyst: Any
) -> None:
    create_baseline(client)

    with pytest.raises(ProgrammingError, match="permission denied"):
        db.execute("DELETE FROM fim_baselines")
    with pytest.raises(ProgrammingError, match="permission denied"):
        db.execute("UPDATE fim_baseline_entries SET sha256 = NULL")
