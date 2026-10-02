"""Playbooks end to end on real Postgres and Redis (Phase 12 acceptance).

The orchestrator (``execute_playbook``) runs in-process on its own event loop,
exactly as in a worker, executing each step through the real run service and
``execute_run``. Purpose-built test playbooks and tools cover the rules:
step references, ``on_failure`` stop/continue, optional missing tools,
cancellation propagation, scope and authorisation, and unified findings.
"""

import asyncio
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from starlette.websockets import WebSocketDisconnect

from app.core.auth.roles import Role
from app.core.runs import events
from app.db import session as db_session
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.registry import registry
from app.engine.schemas import Finding, ToolCategory
from app.playbooks.dispatch import get_playbook_dispatcher
from app.playbooks.engine import execute_playbook
from app.playbooks.loader import definitions
from app.playbooks.schemas import PlaybookDefinition
from tests.integration.conftest import Database, csrf, login, run

# --- test tools ---------------------------------------------------------------------------------


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FailingTool(BaseTool[NoParams]):
    tool_id = "pb_fails"
    name = "Always fails"
    description = "test"
    version = "1.0.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = NoParams

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        raise RuntimeError("boom")

    def translate(self, raw: RawOutput, params: NoParams) -> list[Finding]:
        return []


CANCEL_TARGET: dict[str, uuid.UUID] = {}


class CancelMidRunTool(BaseTool[NoParams]):
    """Simulates the user pressing Cancel on the playbook while this step runs."""

    tool_id = "pb_cancel_mid_run"
    name = "Cancel mid-run"
    description = "test"
    version = "1.0.0"
    category = ToolCategory.DIAGNOSTIC
    params_model = NoParams

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        await events.request_playbook_cancel(CANCEL_TARGET["playbook_run_id"])
        for i in range(100):
            await ctx.report_progress(i, "working")  # the orchestrator forwards the cancel
            await ctx.raise_if_cancelled()
            await asyncio.sleep(0.05)
        return {}

    def translate(self, raw: RawOutput, params: NoParams) -> list[Finding]:
        return []


TOOLS = (FailingTool, CancelMidRunTool)


def pb(playbook_id: str, steps: list[dict[str, Any]], **extra: Any) -> PlaybookDefinition:
    return PlaybookDefinition.model_validate(
        {
            "id": playbook_id,
            "name": playbook_id.replace("_", " ").title(),
            "version": "1.0.0",
            "description": "test playbook",
            "target_input": "target",
            "inputs": {"target": {"kind": "string", "title": "Target"}},
            "steps": steps,
            **extra,
        }
    )


TEST_PLAYBOOKS = [
    pb(
        "t_chain",
        [
            {
                "id": "first",
                "name": "First",
                "tool_id": "echo",
                "params": {"message": "{{ inputs.target }}"},
            },
            {
                "id": "second",
                "name": "Second",
                "tool_id": "echo",
                "params": {"message": "from first: {{ steps.first.echoes[0] }}", "repeat": 2},
            },
            {
                "id": "later",
                "name": "Later phase",
                "tool_id": "not_installed_yet",
                "optional": True,
            },
        ],
    ),
    pb(
        "t_stop",
        [
            {"id": "bad", "name": "Bad", "tool_id": "pb_fails", "on_failure": "stop"},
            {"id": "after", "name": "After", "tool_id": "echo", "params": {"message": "x"}},
        ],
    ),
    pb(
        "t_continue",
        [
            {"id": "bad", "name": "Bad", "tool_id": "pb_fails", "on_failure": "continue"},
            {"id": "after", "name": "After", "tool_id": "echo", "params": {"message": "x"}},
        ],
    ),
    pb(
        "t_ref_error",
        [
            {"id": "first", "name": "First", "tool_id": "echo", "params": {"message": "x"}},
            {
                "id": "second",
                "name": "Second",
                "tool_id": "echo",
                "params": {"message": "{{ steps.first.no_such_field }}"},
                "on_failure": "stop",
            },
            {"id": "third", "name": "Third", "tool_id": "echo", "params": {"message": "x"}},
        ],
    ),
    pb(
        "t_cancel",
        [
            {"id": "slow", "name": "Slow", "tool_id": "pb_cancel_mid_run"},
            {"id": "after", "name": "After", "tool_id": "echo", "params": {"message": "x"}},
        ],
    ),
    pb(
        "t_needs_missing",
        [
            {"id": "needs", "name": "Needs", "tool_id": "not_installed_yet"},
        ],
    ),
    pb(
        "t_active",
        [
            {
                "id": "scan",
                "name": "Scan",
                "tool_id": "port_scanner",
                "params": {
                    "target": "{{ inputs.target }}",
                    "preset": "custom",
                    "ports": "22",
                    "cve_lookup": False,
                },
            },
        ],
        inputs={"target": {"kind": "host", "title": "Target"}},
    ),
]


@pytest.fixture(autouse=True)
def test_playbooks() -> Iterator[None]:
    for tool in TOOLS:
        registry.register(tool)
    loaded = definitions()
    for definition in TEST_PLAYBOOKS:
        loaded[definition.id] = definition
    yield
    for definition in TEST_PLAYBOOKS:
        loaded.pop(definition.id, None)
    for tool in TOOLS:
        registry._tools.pop(tool.tool_id, None)


class Captured:
    def __init__(self) -> None:
        self.sent: list[uuid.UUID] = []
        self.revoked: list[str] = []

    def send(self, playbook_run_id: uuid.UUID, definition: Any) -> str:
        self.sent.append(playbook_run_id)
        return f"pb-task-{playbook_run_id}"

    def revoke(self, task_id: str) -> None:
        self.revoked.append(task_id)


@pytest.fixture
def dispatcher(app: FastAPI) -> Iterator[Captured]:
    captured = Captured()
    app.dependency_overrides[get_playbook_dispatcher] = lambda: captured
    yield captured
    app.dependency_overrides.pop(get_playbook_dispatcher, None)


@pytest.fixture
def analyst(client: TestClient, make_user: Callable[..., Any]) -> Any:
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    return user_id


def start(client: TestClient, playbook_id: str, target: str = "hello") -> Any:
    return client.post(
        f"/api/v1/playbooks/{playbook_id}/runs",
        json={"inputs": {"target": target}},
        headers=csrf(client),
    )


def run_playbook(playbook_run_id: str) -> str:
    """Run the orchestrator like a worker process: its own loop, engine and Redis client."""
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()

    async def go() -> str:
        try:
            return await execute_playbook(uuid.UUID(playbook_run_id))
        finally:
            await db_session.dispose_engine()
            await events.close_redis()

    try:
        return run(go())
    finally:
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


def statuses(detail: dict[str, Any]) -> dict[str, str]:
    return {s["step_id"]: s["status"] for s in detail["steps"]}


# --- tests -----------------------------------------------------------------------------


def test_catalogue_reports_availability(client: TestClient, analyst: Any) -> None:
    catalogue = {p["id"]: p for p in client.get("/api/v1/playbooks").json()}
    audit = catalogue["web_defensive_audit"]
    assert audit["available"] is True and audit["requires_authorization"] is True
    assert {s["id"]: s["available"] for s in audit["steps"]}["intel"] is False
    assert catalogue["t_needs_missing"]["available"] is False
    assert "not installed" in catalogue["t_needs_missing"]["unavailable_reason"]
    assert audit["inputs_schema"]["required"] == ["target"]


def test_full_run_with_references_optional_skip_and_unified_findings(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    response = start(client, "t_chain", "Hello")
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "QUEUED" and statuses(body) == {
        "first": "PENDING",
        "second": "PENDING",
        "later": "PENDING",
    }
    playbook_run_id = body["playbook_run_id"]
    assert dispatcher.sent == [uuid.UUID(playbook_run_id)]

    assert run_playbook(playbook_run_id) == "COMPLETED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert detail["status"] == "COMPLETED" and detail["progress_pct"] == 100
    assert statuses(detail) == {"first": "COMPLETED", "second": "COMPLETED", "later": "SKIPPED"}
    second = next(s for s in detail["steps"] if s["step_id"] == "second")
    # The reference to the first step's output was resolved by the safe resolver.
    assert second["resolved_params"] == {"message": "from first: Hello", "repeat": 2}
    later = next(s for s in detail["steps"] if s["step_id"] == "later")
    assert later["error"]["code"] == "tool_not_installed"

    # Both echo steps report the same finding: unified into one, with provenance.
    assert len(detail["findings"]) == 1
    unified = detail["findings"][0]
    assert unified["step_id"] == "first" and unified["also_reported_by"] == ["second"]
    assert detail["risk"]["highest"] == "INFO"

    # Each executed step is a normal, linked, audited tool run.
    runs = db.execute("SELECT * FROM tool_runs ORDER BY created_at")
    assert [r["playbook_run_id"] for r in runs] == [uuid.UUID(playbook_run_id)] * 2
    actions = [e["action"] for e in db.audit()]
    for expected in (
        "playbook.run.requested",
        "playbook.run.started",
        "tool.run.requested",
        "tool.run.completed",
        "playbook.run.completed",
    ):
        assert expected in actions
    assert db.audit("playbook.run.completed")[0]["details"]["steps"]["later"] == "SKIPPED"


def test_on_failure_stop_skips_the_rest(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_stop").json()["playbook_run_id"]
    assert run_playbook(playbook_run_id) == "FAILED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert statuses(detail) == {"bad": "FAILED", "after": "SKIPPED"}
    assert detail["error"]["code"] == "step_failed"
    after = next(s for s in detail["steps"] if s["step_id"] == "after")
    assert after["error"]["code"] == "stopped"


def test_on_failure_continue_runs_the_rest(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_continue").json()["playbook_run_id"]
    assert run_playbook(playbook_run_id) == "COMPLETED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert statuses(detail) == {"bad": "FAILED", "after": "COMPLETED"}
    bad = next(s for s in detail["steps"] if s["step_id"] == "bad")
    assert bad["error"]["code"] == "tool_error"
    assert "coverage is partial" in detail["risk"]["headline"]


def test_unresolvable_reference_fails_the_step_and_honours_stop(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_ref_error").json()["playbook_run_id"]
    assert run_playbook(playbook_run_id) == "FAILED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert statuses(detail) == {"first": "COMPLETED", "second": "FAILED", "third": "SKIPPED"}
    second = next(s for s in detail["steps"] if s["step_id"] == "second")
    assert second["error"]["code"] == "reference_error"
    assert "no_such_field" in second["error"]["message"]


def test_cancel_propagates_into_the_running_step(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_cancel").json()["playbook_run_id"]
    CANCEL_TARGET["playbook_run_id"] = uuid.UUID(playbook_run_id)
    assert run_playbook(playbook_run_id) == "CANCELLED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert statuses(detail) == {"slow": "CANCELLED", "after": "CANCELLED"}
    slow = next(s for s in detail["steps"] if s["step_id"] == "slow")
    assert slow["run"]["status"] == "CANCELLED"  # the tool itself stopped
    assert db.audit("playbook.run.cancelled")
    assert db.audit("tool.run.cancelled")


def test_cancel_while_queued(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_chain").json()["playbook_run_id"]
    response = client.post(f"/api/v1/playbook-runs/{playbook_run_id}/cancel", headers=csrf(client))
    assert response.status_code == 200
    assert response.json()["status"] == "CANCELLED"
    assert dispatcher.revoked == [f"pb-task-{playbook_run_id}"]
    assert run_playbook(playbook_run_id) == "CANCELLED"  # the orchestrator never starts it
    assert db.audit("playbook.run.started") == []
    again = client.post(f"/api/v1/playbook-runs/{playbook_run_id}/cancel", headers=csrf(client))
    assert again.status_code == 409


def test_redelivered_running_playbook_is_failed_not_rerun(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_chain").json()["playbook_run_id"]
    db.execute(
        "UPDATE playbook_runs SET status = 'RUNNING', started_at = now() WHERE id = :id",
        {"id": playbook_run_id},
    )
    assert run_playbook(playbook_run_id) == "FAILED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    assert detail["error"]["code"] == "worker_lost"
    assert db.execute("SELECT count(*) AS n FROM tool_runs")[0]["n"] == 0


def test_start_validation_role_and_availability(
    client: TestClient, make_user: Callable[..., Any], db: Database, dispatcher: Captured
) -> None:
    make_user("ana", Role.ANALYST)
    login(client, "ana")
    assert (
        client.post(
            "/api/v1/playbooks/nope/runs", json={"inputs": {}}, headers=csrf(client)
        ).status_code
        == 404
    )
    missing = client.post(
        "/api/v1/playbooks/t_chain/runs", json={"inputs": {}}, headers=csrf(client)
    )
    assert missing.status_code == 422
    assert missing.json()["error"]["details"]["errors"][0]["loc"] == ["inputs", "target"]
    assert start(client, "t_needs_missing").status_code == 409

    make_user("vic", Role.VIEWER)
    login(client, "vic")
    assert start(client, "t_chain").status_code == 403
    assert dispatcher.sent == []


def test_active_playbooks_need_acknowledgement_and_scope(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    response = start(client, "t_active", "127.0.0.1")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_required"
    client.post(
        "/api/v1/scope/acknowledgement", json={"statement_version": 1}, headers=csrf(client)
    )
    denied = start(client, "t_active", "8.8.8.8")
    assert denied.status_code == 403
    assert denied.json()["error"]["details"]["reason"] == "out_of_scope"
    [event] = db.audit("tool.run.denied_scope")
    assert event["details"]["tool_id"] == "playbook:t_active"
    assert dispatcher.sent == []
    assert start(client, "t_active", "127.0.0.1").status_code == 202


def test_history_and_quota(client: TestClient, analyst: Any, dispatcher: Captured) -> None:
    ids = [start(client, "t_chain").json()["playbook_run_id"] for _ in range(3)]
    # Three queued playbooks fill the per-user cap shared with manual tool runs.
    capped = start(client, "t_chain")
    assert capped.status_code == 429
    tool_run = client.post(
        "/api/v1/tools/echo/runs", json={"params": {"message": "x"}}, headers=csrf(client)
    )
    assert tool_run.status_code == 429
    page = client.get("/api/v1/playbook-runs", params={"limit": 2}).json()
    assert [r["playbook_run_id"] for r in page["runs"]] == ids[::-1][:2]
    assert page["next_before"] == ids[1]


def test_playbook_websocket_requires_a_playbook_ticket(
    client: TestClient, analyst: Any, dispatcher: Captured
) -> None:
    playbook_run_id = start(client, "t_chain").json()["playbook_run_id"]
    ticket = client.post(
        f"/api/v1/playbook-runs/{playbook_run_id}/ws-ticket", headers=csrf(client)
    ).json()["ticket"]
    with client.websocket_connect(f"/ws/playbooks/{playbook_run_id}?ticket={ticket}") as ws:
        first = ws.receive_json()
        assert first["type"] == "playbook.update" and first["status"] == "QUEUED"

    # A ticket issued for a tool run cannot open a playbook stream (and vice versa).
    created = client.post(
        "/api/v1/tools/echo/runs", json={"params": {"message": "x"}}, headers=csrf(client)
    )
    assert created.status_code == 202, created.text
    run_ticket = client.post(
        f"/api/v1/runs/{created.json()['run_id']}/ws-ticket", headers=csrf(client)
    ).json()["ticket"]
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect(f"/ws/playbooks/{playbook_run_id}?ticket={run_ticket}") as ws,
    ):
        ws.receive_text()
    assert exc.value.code == 1008


def test_playbook_tables_are_not_deletable_by_the_app(
    client: TestClient, db: Database, analyst: Any, dispatcher: Captured
) -> None:
    start(client, "t_chain")
    with pytest.raises(Exception, match="permission denied"):
        db.execute("DELETE FROM playbook_runs")
    with pytest.raises(Exception, match="permission denied"):
        db.execute("DELETE FROM playbook_steps")
