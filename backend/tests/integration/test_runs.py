"""Tool runs end to end on real Postgres and Redis: API, worker logic, WebSocket.

The Celery broker is replaced by a capturing dispatcher, and the worker's
``execute_run`` is called in-process. That exercises the real claim, execute,
persist and audit code on the real database without a worker container.
"""

import asyncio
import json
import uuid
from collections.abc import Callable, Iterator
from typing import Any, ClassVar

import pytest
import redis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from starlette.websockets import WebSocketDisconnect

from app.core.auth.roles import Role
from app.core.runs import events
from app.core.runs.dispatch import get_dispatcher
from app.core.tasks.tool_task import execute_run
from app.db import session as db_session
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.registry import registry
from app.engine.schemas import Finding, FindingStatus, Severity, ToolCategory
from tests.integration.conftest import ORIGIN, REDIS_URL, Database, csrf, login, run

# --- test doubles ----------------------------------------------------------------


class Captured:
    def __init__(self) -> None:
        self.sent: list[tuple[uuid.UUID, str]] = []
        self.revoked: list[str] = []
        self.fail = False

    def send(self, run_id: uuid.UUID, tool: type[BaseTool[Any]]) -> str:
        if self.fail:
            raise ConnectionError("broker down")
        self.sent.append((run_id, tool.tool_id))
        return f"task-{run_id}"

    def revoke(self, task_id: str) -> None:
        self.revoked.append(task_id)


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _TestTool(BaseTool[NoParams]):
    description = "test tool"
    version = "1.0.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = NoParams

    def translate(self, raw: RawOutput, params: NoParams) -> list[Finding]:
        return [
            Finding(
                item="Test finding",
                category="TEST",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                severity_rationale="Test rationale.",
                explanation="Test explanation.",
                remediation="Test remediation.",
            )
        ]


class CancelsItselfTool(_TestTool):
    """Simulates a cancel arriving mid-run, then honours it cooperatively."""

    tool_id = "it_cancels_itself"
    name = "Cancels itself"

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        await ctx.report_progress(10, "working")
        await events.request_cancel(ctx.run_id)
        for _ in range(50):
            await ctx.raise_if_cancelled()
            await asyncio.sleep(0.05)
        return {}


class SleepyTool(_TestTool):
    tool_id = "it_sleepy"
    name = "Sleepy"
    soft_time_limit = 1
    hard_time_limit = 5

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        await asyncio.sleep(10)
        return {}


class BigOutputTool(_TestTool):
    tool_id = "it_big_output"
    name = "Big output"

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        return {"blob": "x" * 2_000_000}


class ActiveTool(_TestTool):
    tool_id = "it_active"
    name = "Active"
    is_active = True

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        raise AssertionError("must never run without a scope policy")


class AdminOnlyTool(_TestTool):
    tool_id = "it_admin_only"
    name = "Admin only"
    required_role: ClassVar[Role] = Role.ADMIN

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        return {}


TEST_TOOLS = (CancelsItselfTool, SleepyTool, BigOutputTool, ActiveTool, AdminOnlyTool)


@pytest.fixture(autouse=True)
def test_tools() -> Iterator[None]:
    for tool in TEST_TOOLS:
        registry.register(tool)
    yield
    for tool in TEST_TOOLS:
        registry._tools.pop(tool.tool_id, None)


@pytest.fixture
def dispatcher(app: FastAPI) -> Iterator[Captured]:
    captured = Captured()
    app.dependency_overrides[get_dispatcher] = lambda: captured
    yield captured
    app.dependency_overrides.pop(get_dispatcher, None)


@pytest.fixture
def analyst(client: TestClient, make_user: Callable[..., Any]) -> Any:
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    return user_id


def start(client: TestClient, tool_id: str, params: dict[str, Any] | None = None) -> Any:
    return client.post(
        f"/api/v1/tools/{tool_id}/runs", json={"params": params or {}}, headers=csrf(client)
    )


def run_worker(run_id: str) -> str:
    """Run the worker's task body on its own event loop and engine, like a worker process.

    The TestClient's loop owns the API's pooled connections; the worker must
    not borrow them, so its engine and Redis client are swapped out and
    disposed afterwards.
    """
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()

    async def go() -> str:
        try:
            return await execute_run(uuid.UUID(run_id))
        finally:
            await db_session.dispose_engine()
            await events.close_redis()

    try:
        return run(go())
    finally:
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


# --- creating runs ---------------------------------------------------------------


def test_analyst_starts_a_run_which_is_queued_and_audited(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    response = start(client, "echo", {"message": "hello", "repeat": 2})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "QUEUED"
    assert body["tool_id"] == "echo"
    assert body["initiated_by"] == "ana"
    assert body["params"] == {"message": "hello", "repeat": 2}

    run_id = body["run_id"]
    assert dispatcher.sent == [(uuid.UUID(run_id), "echo")]
    row = db.execute("SELECT * FROM tool_runs WHERE id = :id", {"id": run_id})[0]
    assert row["status"] == "QUEUED"
    assert row["celery_task_id"] == f"task-{run_id}"
    assert row["user_id"] == analyst
    [event] = db.audit("tool.run.requested")
    assert event["resource_id"] == run_id
    assert event["username"] == "ana"


def test_viewer_cannot_start_runs(
    client: TestClient, db: Database, make_user: Callable[..., Any], dispatcher: Captured
) -> None:
    make_user("vic", Role.VIEWER)
    login(client, "vic")
    assert start(client, "echo", {"message": "x"}).status_code == 403
    assert dispatcher.sent == []
    assert db.audit("auth.access.denied")


def test_tool_required_role_is_enforced(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    response = start(client, "it_admin_only")
    assert response.status_code == 403
    [denied] = db.audit("auth.access.denied")
    assert denied["target"] == "tool:it_admin_only"


def test_invalid_params_are_rejected_without_echoing_input(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    secretish = "s3cr3t-" + "x" * 600
    response = start(client, "echo", {"message": secretish, "unknown": 1})
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "validation_failed"
    locs = [e["loc"] for e in body["details"]["errors"]]
    assert ["params", "message"] in locs and ["params", "unknown"] in locs
    assert "s3cr3t" not in response.text
    assert dispatcher.sent == []


def test_unknown_tool(client: TestClient, analyst: Any, dispatcher: Captured) -> None:
    response = start(client, "no_such_tool")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "tool_not_found"


def test_active_tools_are_denied_until_scope_policy_exists(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    response = start(client, "it_active")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "scope_denied"
    [event] = db.audit("tool.run.denied_scope")
    assert event["is_security_event"] is True
    assert dispatcher.sent == []
    assert db.execute("SELECT count(*) AS n FROM tool_runs")[0]["n"] == 0


def test_run_creation_requires_csrf(client: TestClient, analyst: Any, dispatcher: Captured) -> None:
    response = client.post("/api/v1/tools/echo/runs", json={"params": {"message": "x"}})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_active_run_quota(client: TestClient, analyst: Any, dispatcher: Captured) -> None:
    for _ in range(3):
        assert start(client, "echo", {"message": "x"}).status_code == 202
    response = start(client, "echo", {"message": "x"})
    assert response.status_code == 429
    assert "3 runs in progress" in response.json()["error"]["message"]


def test_broker_failure_marks_run_failed(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    dispatcher.fail = True
    response = start(client, "echo", {"message": "x"})
    assert response.status_code == 503
    [row] = db.execute("SELECT status, errors FROM tool_runs")
    assert row["status"] == "FAILED"
    assert row["errors"][0]["code"] == "dispatch_failed"
    assert db.audit("tool.run.failed")


# --- the worker ------------------------------------------------------------------


def test_worker_completes_run_with_findings_and_audit(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "hello", "repeat": 3}).json()["run_id"]
    assert run_worker(run_id) == "COMPLETED"

    detail = client.get(f"/api/v1/runs/{run_id}").json()
    assert detail["status"] == "COMPLETED"
    assert detail["progress_pct"] == 100
    assert detail["summary"]["total"] == 1
    assert detail["findings"][0]["item"] == "Echo round trip succeeded"
    assert detail["raw_data"]["echoes"] == ["hello"] * 3
    assert detail["duration_ms"] is not None
    actions = [e["action"] for e in db.audit()]
    assert actions[-3:] == ["tool.run.requested", "tool.run.started", "tool.run.completed"]
    started = db.audit("tool.run.started")[0]
    assert started["service"] == "worker"
    assert started["username"] == "ana"


def test_worker_never_runs_a_cancelled_queued_run(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    cancelled = client.post(f"/api/v1/runs/{run_id}/cancel", headers=csrf(client))
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert dispatcher.revoked == [f"task-{run_id}"]
    assert run_worker(run_id) == "CANCELLED"
    assert db.audit("tool.run.started") == []
    assert db.audit("tool.run.cancelled")[0]["details"]["stage"] == "queued"


def test_cooperative_cancel_while_running(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "it_cancels_itself").json()["run_id"]
    assert run_worker(run_id) == "CANCELLED"
    assert db.audit("tool.run.cancelled")


def test_cancel_of_running_run_sets_the_flag(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    db.execute("UPDATE tool_runs SET status = 'RUNNING' WHERE id = :id", {"id": run_id})
    response = client.post(f"/api/v1/runs/{run_id}/cancel", headers=csrf(client))
    assert response.status_code == 200
    assert response.json()["status"] == "RUNNING"
    assert response.json()["cancel_requested"] is True
    assert REDIS_URL is not None
    with redis.Redis.from_url(REDIS_URL) as r:
        assert r.exists(f"sentinel:run:{run_id}:cancel")


def test_cannot_cancel_someone_elses_run_or_a_finished_one(
    client: TestClient,
    db: Database,
    make_user: Callable[..., Any],
    analyst: Any,
    dispatcher: Captured,
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    make_user("bob", Role.ANALYST)
    login(client, "bob")
    response = client.post(f"/api/v1/runs/{run_id}/cancel", headers=csrf(client))
    assert response.status_code == 403
    assert db.audit("auth.access.denied")[0]["reason"] == "not_run_owner"

    run_worker(run_id)
    login(client, "ana")
    response = client.post(f"/api/v1/runs/{run_id}/cancel", headers=csrf(client))
    assert response.status_code == 409


def test_soft_time_limit_gives_timed_out(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "it_sleepy").json()["run_id"]
    assert run_worker(run_id) == "TIMED_OUT"
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    assert detail["errors"] == [
        {"code": "tool_timeout", "message": "The tool exceeded its time limit."}
    ]
    assert db.audit("tool.run.failed")[0]["details"]["status"] == "TIMED_OUT"


def test_redelivered_running_run_is_failed_not_rerun(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    db.execute(
        "UPDATE tool_runs SET status = 'RUNNING', started_at = now() WHERE id = :id",
        {"id": run_id},
    )
    assert run_worker(run_id) == "FAILED"
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    assert detail["errors"][0]["code"] == "worker_lost"
    assert db.audit("tool.run.started") == []


def test_raw_output_is_capped(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "it_big_output").json()["run_id"]
    assert run_worker(run_id) == "COMPLETED"
    raw = client.get(f"/api/v1/runs/{run_id}").json()["raw_data"]
    assert raw["_truncated"] is True


def test_findings_are_insert_only_for_the_app_role(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    run_worker(run_id)
    with pytest.raises(Exception, match="permission denied"):
        db.execute("UPDATE findings SET severity = 'INFO'")
    with pytest.raises(Exception, match="permission denied"):
        db.execute("DELETE FROM tool_runs")


# --- reading runs ----------------------------------------------------------------


def test_history_lists_filters_and_pages(
    client: TestClient, make_user: Callable[..., Any], analyst: Any, dispatcher: Captured
) -> None:
    ids = [start(client, "echo", {"message": str(i)}).json()["run_id"] for i in range(3)]
    for run_id in ids:
        run_worker(run_id)
    make_user("vera", Role.VIEWER)
    login(client, "vera")

    page = client.get("/api/v1/runs", params={"limit": 2}).json()
    assert [r["run_id"] for r in page["runs"]] == ids[::-1][:2]
    assert page["next_before"] == ids[1]
    rest = client.get("/api/v1/runs", params={"limit": 2, "before": page["next_before"]}).json()
    assert [r["run_id"] for r in rest["runs"]] == [ids[0]]
    assert rest["next_before"] is None
    assert page["runs"][0]["finding_count"] == 1
    assert page["runs"][0]["max_severity"] == "INFO"

    assert client.get("/api/v1/runs", params={"mine": True}).json()["runs"] == []
    assert len(client.get("/api/v1/runs", params={"status": "COMPLETED"}).json()["runs"]) == 3
    assert client.get("/api/v1/runs", params={"tool_id": "dns_lookup"}).json()["runs"] == []


def test_unknown_run_is_404(client: TestClient, analyst: Any) -> None:
    assert client.get(f"/api/v1/runs/{uuid.uuid4()}").status_code == 404


def test_runs_require_authentication(client: TestClient, db: Database) -> None:
    assert client.get("/api/v1/runs").status_code == 401


# --- WebSocket -------------------------------------------------------------------


def ticket(client: TestClient, run_id: str) -> str:
    response = client.post(f"/api/v1/runs/{run_id}/ws-ticket", headers=csrf(client))
    assert response.status_code == 200, response.text
    return str(response.json()["ticket"])


def test_websocket_streams_updates_until_terminal(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    url = f"/ws/runs/{run_id}?ticket={ticket(client, run_id)}"
    assert REDIS_URL is not None
    with client.websocket_connect(url, headers={"Origin": ORIGIN}) as ws:
        first = json.loads(ws.receive_text())
        assert first["status"] == "QUEUED"
        with redis.Redis.from_url(REDIS_URL) as r:
            channel = f"sentinel:run:{run_id}"
            running = events.RunEvent.now(uuid.UUID(run_id), "RUNNING", progress_pct=40)
            r.publish(channel, running.to_json())
            update = json.loads(ws.receive_text())
            assert (update["status"], update["progress_pct"]) == ("RUNNING", 40)
            done = events.RunEvent.now(uuid.UUID(run_id), "COMPLETED", progress_pct=100)
            r.publish(channel, done.to_json())
            assert json.loads(ws.receive_text())["status"] == "COMPLETED"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_websocket_ticket_is_single_use_and_run_bound(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    other_id = start(client, "echo", {"message": "y"}).json()["run_id"]
    run_worker(run_id)
    t = ticket(client, run_id)
    with client.websocket_connect(f"/ws/runs/{run_id}?ticket={t}") as ws:
        assert json.loads(ws.receive_text())["status"] == "COMPLETED"

    for url in (
        f"/ws/runs/{run_id}?ticket={t}",  # reused
        f"/ws/runs/{other_id}?ticket={ticket(client, run_id)}",  # wrong run
        f"/ws/runs/{run_id}",  # missing
        f"/ws/runs/{run_id}?ticket=forged",
    ):
        with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect(url) as ws:
            ws.receive_text()
        assert exc.value.code == 1008


def test_websocket_rejects_foreign_origin(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    run_id = start(client, "echo", {"message": "x"}).json()["run_id"]
    url = f"/ws/runs/{run_id}?ticket={ticket(client, run_id)}"
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect(url, headers={"Origin": "https://evil.example"}) as ws,
    ):
        ws.receive_text()
    assert exc.value.code == 1008
