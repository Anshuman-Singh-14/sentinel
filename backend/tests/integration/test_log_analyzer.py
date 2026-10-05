"""Log analyzer end to end on real Postgres and Redis (Phase 10, ADR 0014).

Upload route -> stored file -> run -> Celery task body -> findings -> file
deleted, with the audit trail, the size limit, traversal refusal and the
Phase 13 exporters (ADR 0009 checklist).
"""

import csv
import io
import json
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.auth.roles import Role
from app.core.runs import events
from app.core.runs.dispatch import get_dispatcher
from app.core.tasks import loop
from app.core.tasks.tool_task import run_tool
from app.db import session as db_session
from app.reports.dispatch import get_report_dispatcher
from app.reports.generate import generate_report
from tests.integration.conftest import Database, csrf, login, run

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "logs"
UPLOAD_URL = "/api/v1/tools/log_analyzer/runs/upload"


class Captured:
    def __init__(self) -> None:
        self.sent: list[uuid.UUID] = []

    def send(self, item_id: uuid.UUID, *_: Any) -> str:
        self.sent.append(item_id)
        return f"task-{item_id}"

    def revoke(self, task_id: str) -> None:
        return None


@pytest.fixture
def dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    uploads, logs = tmp_path / "uploads", tmp_path / "logs"
    logs.mkdir()
    (logs / "auth.log").write_bytes((FIXTURES / "auth.log").read_bytes())
    (tmp_path / "secret.txt").write_text("not for you", encoding="utf-8")
    monkeypatch.setenv("UPLOAD_DIR", str(uploads))
    monkeypatch.setenv("LOG_ROOT", str(logs))
    get_settings.cache_clear()
    yield uploads, logs
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def analyst(
    app: FastAPI, client: TestClient, make_user: Callable[..., Any], dirs: tuple[Path, Path]
) -> Iterator[Any]:
    for dependency in (get_dispatcher, get_report_dispatcher):
        app.dependency_overrides[dependency] = Captured
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    yield user_id
    for dependency in (get_dispatcher, get_report_dispatcher):
        app.dependency_overrides.pop(dependency, None)


def as_celery_task(run_id: str) -> str:
    """Run the real Celery task body (including its upload cleanup) in this process."""
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()
    try:
        result: str = run_tool.run(run_id)
        loop.run_async(db_session.dispose_engine())
        loop.run_async(events.close_redis())
        return result
    finally:
        loop.reset_loop()
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


def upload(client: TestClient, data: bytes, filename: str, params: dict[str, Any]) -> Any:
    return client.post(
        UPLOAD_URL,
        params={"filename": filename, "params": json.dumps(params)},
        content=data,
        headers={**csrf(client), "Content-Type": "application/octet-stream"},
    )


def test_catalogue_advertises_uploads(client: TestClient, analyst: Any) -> None:
    tools = {t["tool_id"]: t for t in client.get("/api/v1/tools").json()}
    tool = tools["log_analyzer"]
    assert tool["accepts_upload"] is True and tool["max_upload_bytes"] == 50 * 1024 * 1024
    assert tool["category"] == "FORENSIC" and tool["is_active"] is False
    assert tools["echo"]["accepts_upload"] is False


def test_upload_end_to_end(
    client: TestClient, db: Database, analyst: Any, dirs: tuple[Path, Path]
) -> None:
    uploads, _ = dirs
    data = (FIXTURES / "auth.log").read_bytes()

    response = upload(client, data, "../../evil\\auth.log", {"parser": "auto"})

    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    assert response.json()["target"] == "auth.log"  # directory parts stripped
    assert response.json()["params"]["upload_name"] == "auth.log"
    stored = uploads / f"{run_id}.upload"
    assert stored.read_bytes() == data

    (requested,) = db.audit("tool.run.requested")
    assert requested["details"]["upload"] == {"name": "auth.log", "bytes": len(data)}
    (analysis,) = db.audit("log.analysis.requested")
    assert analysis["resource_id"] == run_id and analysis["target"] == "auth.log"
    audit_text = json.dumps([dict(r) for r in db.audit()], default=str)
    assert "Failed password" not in audit_text  # names and sizes only, never contents

    assert as_celery_task(run_id) == "COMPLETED"
    assert not stored.exists()  # deleted after processing
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    severities = [f["severity"] for f in detail["findings"]]
    assert severities[:2] == ["HIGH", "HIGH"] and detail["summary"]["total"] == 6
    assert detail["raw_data"]["source"] == {
        "kind": "upload",
        "name": "auth.log",
        "bytes": len(data),
    }

    # Phase 13 exporters render the new findings unchanged (ADR 0009 checklist).
    for fmt in ("pdf", "csv"):
        report_id = client.post(
            "/api/v1/reports",
            json={"source_type": "tool_run", "source_id": run_id, "format": fmt},
            headers=csrf(client),
        ).json()["report_id"]
        rid = uuid.UUID(report_id)
        saved = (db_session._engine, db_session._sessionmaker)
        db_session.forget_engine()
        try:
            assert run(_generate(rid)) == "COMPLETED"
        finally:
            db_session._engine, db_session._sessionmaker = saved
        content = client.get(f"/api/v1/reports/{report_id}/download").content
        if fmt == "pdf":
            assert content.startswith(b"%PDF-")
        else:
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
            assert any("203.0.113.77" in row["item"] for row in rows)


async def _generate(report_id: uuid.UUID) -> str:
    try:
        return await generate_report(report_id)
    finally:
        await db_session.dispose_engine()


def test_upload_limits_and_validation_happen_before_storage(
    client: TestClient,
    db: Database,
    analyst: Any,
    dirs: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uploads, _ = dirs
    monkeypatch.setenv("LOG_UPLOAD_MAX_MB", "1")
    get_settings.cache_clear()

    too_big = upload(client, b"x" * (1024 * 1024 + 1), "big.log", {})
    assert too_big.status_code == 413 and too_big.json()["error"]["code"] == "payload_too_large"

    bad_parser = upload(client, b"data", "a.log", {"parser": "apache_error"})
    assert bad_parser.status_code == 422
    assert bad_parser.json()["error"]["details"]["errors"][0]["loc"] == ["params", "parser"]

    both = upload(client, b"data", "a.log", {"path": "auth.log"})
    assert both.status_code == 422

    not_json = client.post(
        UPLOAD_URL,
        params={"filename": "a.log", "params": "[1]"},
        content=b"data",
        headers=csrf(client),
    )
    assert not_json.status_code == 422

    empty = upload(client, b"", "empty.log", {})
    assert empty.status_code == 422

    assert db.execute("SELECT count(*) AS n FROM tool_runs")[0]["n"] == 0
    assert not uploads.exists() or list(uploads.iterdir()) == []


def test_only_upload_tools_and_analysts(
    client: TestClient, analyst: Any, make_user: Callable[..., Any]
) -> None:
    echo = client.post(
        "/api/v1/tools/echo/runs/upload",
        params={"filename": "a.log"},
        content=b"x",
        headers=csrf(client),
    )
    assert echo.status_code == 404

    make_user("vic", Role.VIEWER)
    client.cookies.clear()
    login(client, "vic")
    assert upload(client, b"x", "a.log", {}).status_code == 403


def test_log_root_run_and_traversal_refusal(client: TestClient, db: Database, analyst: Any) -> None:
    for path in ["../secret.txt", "/etc/passwd", "logs/../../secret.txt", "a\x00.log"]:
        refused = client.post(
            "/api/v1/tools/log_analyzer/runs",
            json={"params": {"path": path}},
            headers=csrf(client),
        )
        assert refused.status_code == 422, path
    assert db.execute("SELECT count(*) AS n FROM tool_runs")[0]["n"] == 0

    started = client.post(
        "/api/v1/tools/log_analyzer/runs",
        json={"params": {"path": "auth.log"}},
        headers=csrf(client),
    )
    assert started.status_code == 202
    assert as_celery_task(started.json()["run_id"]) == "COMPLETED"
    detail = client.get(f"/api/v1/runs/{started.json()['run_id']}").json()
    assert detail["raw_data"]["source"]["kind"] == "log_root"


def test_a_run_cannot_read_another_runs_upload(
    client: TestClient, analyst: Any, dirs: tuple[Path, Path]
) -> None:
    uploads, _ = dirs
    first = upload(client, (FIXTURES / "auth.log").read_bytes(), "auth.log", {}).json()
    # The JSON route accepts upload_name, but the run looks only for its own id.
    forged = client.post(
        "/api/v1/tools/log_analyzer/runs",
        json={"params": {"upload_name": "auth.log"}},
        headers=csrf(client),
    ).json()
    assert as_celery_task(forged["run_id"]) == "FAILED"
    detail = client.get(f"/api/v1/runs/{forged['run_id']}").json()
    assert detail["errors"][0]["code"] == "not_found"
    assert (uploads / f"{first['run_id']}.upload").exists()  # untouched
