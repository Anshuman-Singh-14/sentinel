"""Scope policy, authorised-use acknowledgement and the port scanner, end to end.

Runs in the compose `test` service (internal network only), so:
* "postgres" resolves to Sentinel's own database: the hard denylist must stop it;
* 127.0.0.1 is in the default scope, so a scan of a local socket server
  exercises the whole path (API -> worker scope check -> scanner -> findings).
"""

import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.auth.roles import Role
from tests.integration.conftest import Database, csrf, login, run
from tests.integration.test_runs import Captured, dispatcher, run_worker  # noqa: F401

STATEMENT_VERSION = 1


@pytest.fixture
def analyst(client: TestClient, make_user: Callable[..., Any]) -> Any:
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    return user_id


def acknowledge(client: TestClient) -> Any:
    return client.post(
        "/api/v1/scope/acknowledgement",
        json={"statement_version": STATEMENT_VERSION},
        headers=csrf(client),
    )


def scan(client: TestClient, target: str, ports: str = "22") -> Any:
    return client.post(
        "/api/v1/tools/port_scanner/runs",
        json={
            "params": {"target": target, "preset": "custom", "ports": ports, "cve_lookup": False}
        },
        headers=csrf(client),
    )


# --- acknowledgement ---------------------------------------------------------------------


def test_active_tools_need_the_acknowledgement_first(
    client: TestClient,
    db: Database,
    analyst: Any,
    dispatcher: Captured,  # noqa: F811
) -> None:
    response = scan(client, "127.0.0.1")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_required"
    assert dispatcher.sent == []

    status = client.get("/api/v1/scope/acknowledgement").json()
    assert status["acknowledged"] is False and "written permission" in status["statement"]

    assert (
        client.post(
            "/api/v1/scope/acknowledgement", json={"statement_version": 99}, headers=csrf(client)
        ).status_code
        == 409
    )
    first = acknowledge(client)
    assert first.status_code == 200 and first.json()["acknowledged"] is True
    assert acknowledge(client).status_code == 200  # idempotent
    rows = db.execute("SELECT * FROM authorization_acknowledgements")
    assert len(rows) == 1 and rows[0]["source_ip"]
    [event] = db.audit("scope.authorization.acknowledged")
    assert event["username"] == "ana"
    with pytest.raises(Exception, match="permission denied"):
        db.execute("DELETE FROM authorization_acknowledgements")


def test_viewers_cannot_acknowledge(
    client: TestClient, make_user: Callable[..., Any], db: Database
) -> None:
    make_user("vic", Role.VIEWER)
    login(client, "vic")
    assert acknowledge(client).status_code == 403


# --- scope decisions ------------------------------------------------------------------------


@pytest.fixture
def acknowledged(client: TestClient, analyst: Any) -> Any:
    assert acknowledge(client).status_code == 200
    return analyst


def test_out_of_scope_target_is_denied_and_audited(
    client: TestClient,
    db: Database,
    acknowledged: Any,
    dispatcher: Captured,  # noqa: F811
) -> None:
    response = scan(client, "8.8.8.8")
    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "scope_denied"
    assert body["details"]["reason"] == "out_of_scope"
    assert "not in the scan scope" in body["message"]
    assert dispatcher.sent == []
    [event] = db.audit("tool.run.denied_scope")
    assert event["is_security_event"] is True
    assert event["details"]["stage"] == "api"
    assert event["target"] == "8.8.8.8"


@pytest.mark.parametrize("target", ["postgres", "169.254.169.254"])
def test_infrastructure_is_hard_denied(
    client: TestClient,
    db: Database,
    acknowledged: Any,
    dispatcher: Captured,  # noqa: F811
    target: str,
) -> None:
    response = scan(client, target, "5432")
    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason"] == "hard_denied"
    assert db.audit("tool.run.denied_scope")[0]["reason"] == "hard_denied"


def test_worker_makes_the_final_decision_for_names_the_api_cannot_resolve(
    client: TestClient,
    db: Database,
    acknowledged: Any,
    dispatcher: Captured,  # noqa: F811
) -> None:
    response = scan(client, "no-such-lab-host")
    assert response.status_code == 202  # the API defers: it cannot see the lab network
    run_id = response.json()["run_id"]
    assert run_worker(run_id) == "FAILED"
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    assert detail["errors"][0]["code"] == "scope_denied"
    [event] = db.audit("tool.run.denied_scope")
    assert event["details"]["stage"] == "worker"
    assert event["service"] == "worker"


# --- a real scan through the worker -----------------------------------------------------


class _Banner(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")


@pytest.fixture
def banner_server() -> Iterator[int]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Banner)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_scan_of_in_scope_host_finds_the_open_port(
    client: TestClient,
    acknowledged: Any,
    dispatcher: Captured,  # noqa: F811
    banner_server: int,
) -> None:
    closed = free_port()
    response = scan(client, "127.0.0.1", f"{banner_server},{closed}")
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    assert dispatcher.sent[-1][1] == "port_scanner"
    assert run_worker(run_id) == "COMPLETED"

    detail = client.get(f"/api/v1/runs/{run_id}").json()
    raw = detail["raw_data"]
    assert raw["address"] == "127.0.0.1"
    assert [p["port"] for p in raw["open"]] == [banner_server]
    assert raw["open"][0]["banner"] == "SSH-2.0-OpenSSH_7.4"
    assert raw["open"][0]["product"]["name"] == "OpenSSH"
    assert raw["closed_count"] == 1
    items = [f["item"] for f in detail["findings"]]
    assert "1 open TCP port(s) on 127.0.0.1" in items


# --- admin policy management ----------------------------------------------------------------


@pytest.fixture
def admin(client: TestClient, make_user: Callable[..., Any]) -> Any:
    admin_id = make_user("root", Role.ADMIN)
    assert login(client, "root").status_code == 200
    return admin_id


def add(client: TestClient, kind: str, value: str, description: str = "") -> Any:
    return client.post(
        "/api/v1/admin/scope",
        json={"kind": kind, "value": value, "description": description},
        headers=csrf(client),
    )


def test_admin_manages_the_policy_and_every_change_is_audited(
    client: TestClient, db: Database, admin: Any
) -> None:
    created = add(client, "cidr", "192.0.2.17/24", "Test lab")
    assert created.status_code == 201
    entry = created.json()
    assert entry["value"] == "192.0.2.0/24"  # normalised
    assert add(client, "domain", "*.Example.ORG").json()["value"] == "example.org"
    assert add(client, "cidr", "192.0.2.0/24").status_code == 409

    scope = client.get("/api/v1/admin/scope").json()
    values = [r["value"] for r in scope["rules"]]
    assert "10.231.10.0/24" in values and "192.0.2.0/24" in values
    assert "169.254.0.0/16" in scope["hard_deny"] and "10.231.0.0/24" in scope["hard_deny"]

    patched = client.patch(
        f"/api/v1/admin/scope/{entry['id']}", json={"enabled": False}, headers=csrf(client)
    )
    assert patched.json()["enabled"] is False
    assert "192.0.2.0/24" not in [r["value"] for r in client.get("/api/v1/scope").json()["rules"]]
    assert client.get("/api/v1/scope").json()["hard_deny"] is None  # not shown to /scope

    assert (
        client.delete(f"/api/v1/admin/scope/{entry['id']}", headers=csrf(client)).status_code == 204
    )
    changes = db.audit("scope.policy.changed")
    assert [e["details"]["change"] for e in changes] == ["added", "added", "updated", "removed"]
    assert all(e["is_security_event"] for e in changes)


@pytest.mark.parametrize(
    ("kind", "value", "message"),
    [
        ("cidr", "10.231.0.0/16", "never scans"),
        ("cidr", "169.254.169.254", "never scans"),
        ("cidr", "0.0.0.0/0", "too broad"),
        ("cidr", "16.0.0.0/4", "too broad"),
        ("cidr", "not-an-ip", "valid IP"),
        ("domain", "intranet.local", "reserved"),
        ("domain", "localhost", "fully qualified"),
    ],
)
def test_dangerous_or_invalid_entries_are_rejected(
    client: TestClient, admin: Any, kind: str, value: str, message: str
) -> None:
    response = add(client, kind, value)
    assert response.status_code == 422
    assert message in response.json()["error"]["message"]


def test_non_admins_cannot_change_the_policy(
    client: TestClient, db: Database, analyst: Any
) -> None:
    assert add(client, "cidr", "192.0.2.0/24").status_code == 403
    assert client.get("/api/v1/admin/scope").status_code == 403
    assert client.get("/api/v1/scope").status_code == 200


def test_policy_changes_take_effect_immediately(
    client: TestClient,
    make_user: Callable[..., Any],
    admin: Any,
    dispatcher: Captured,  # noqa: F811
) -> None:
    make_user("ana", Role.ANALYST)
    login(client, "ana")
    acknowledge(client)
    assert scan(client, "192.0.2.10").status_code == 403
    login(client, "root")
    add(client, "cidr", "192.0.2.0/28")
    login(client, "ana")
    assert scan(client, "192.0.2.10").status_code == 202


def test_nvd_window_limiter_does_not_count_refused_attempts(db: Database) -> None:
    from app.core.runs import events
    from app.tools.port_scanner.tool import RedisWindowLimiter

    saved = (events._client, events._client_loop)
    events.forget_client()

    async def go() -> str | None:
        try:
            limiter = RedisWindowLimiter()
            assert await limiter.try_acquire("sentinel:test:window", 2, 30) == 0
            assert await limiter.try_acquire("sentinel:test:window", 2, 30) == 0
            for _ in range(5):
                assert await limiter.try_acquire("sentinel:test:window", 2, 30) > 0
            value = await events.get_redis().get("sentinel:test:window")
            return str(value) if value is not None else None
        finally:
            await events.close_redis()

    try:
        assert run(go()) == "2"  # refused attempts were handed back
    finally:
        events._client, events._client_loop = saved
