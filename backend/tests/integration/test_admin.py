"""User administration, session revocation, RBAC on the real auth path, the CLI."""

import io
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.core.audit import build_audit_service
from app.core.audit.context import SYSTEM_ACTOR
from app.core.auth.roles import Role
from app.core.auth.users import update_user
from app.core.errors import Conflict
from app.db.session import dispose_engine, get_sessionmaker
from tests.integration.conftest import (
    PASSWORD,
    Database,
    csrf,
    login,
    restore_cookies,
    run,
    save_cookies,
)


@pytest.fixture
def admin(client: TestClient, make_user: Callable[..., Any]) -> Any:
    admin_id = make_user("root", Role.ADMIN)
    assert login(client, "root").status_code == 200
    return admin_id


def test_admin_creates_user_and_it_is_audited(client: TestClient, db: Database, admin: Any) -> None:
    response = client.post(
        "/api/v1/admin/users",
        json={"username": "Carol", "password": PASSWORD, "role": "viewer"},
        headers=csrf(client),
    )

    assert response.status_code == 201
    assert response.json()["username"] == "carol"
    (event,) = db.audit("user.created")
    assert event["user_id"] == admin  # the actor is the admin
    assert event["username"] == "root"
    assert event["target"] == "carol"
    assert event["resource_id"] == response.json()["id"]
    assert event["details"] == {"role": "viewer"}
    assert PASSWORD not in str(dict(event))


def test_create_user_rejects_duplicates_weak_passwords_and_bad_names(
    client: TestClient, admin: Any
) -> None:
    def create(username: str, password: str = PASSWORD) -> Any:
        return client.post(
            "/api/v1/admin/users",
            json={"username": username, "password": password, "role": "viewer"},
            headers=csrf(client),
        )

    assert create("root").status_code == 409
    assert create("ROOT").status_code == 409  # case-insensitive uniqueness
    assert create("dave", "password1234").json()["error"]["code"] == "password_policy"
    assert create("bad name").status_code == 422
    assert create("x").status_code == 422


def test_role_change_disable_and_enable(
    client: TestClient, db: Database, admin: Any, make_user: Callable[..., Any]
) -> None:
    target = make_user("erin", Role.VIEWER)
    admin_cookies = save_cookies(client)
    client.cookies.clear()
    login(client, "erin")
    erin_cookies = save_cookies(client)
    restore_cookies(client, admin_cookies)

    promoted = client.patch(
        f"/api/v1/admin/users/{target}", json={"role": "analyst"}, headers=csrf(client)
    )
    disabled = client.patch(
        f"/api/v1/admin/users/{target}", json={"is_active": False}, headers=csrf(client)
    )

    assert promoted.json()["role"] == "analyst"
    assert disabled.json()["is_active"] is False
    (role_event,) = db.audit("user.role.changed")
    assert role_event["details"] == {"from": "viewer", "to": "analyst"}
    assert role_event["is_security_event"] is True
    (disable_event,) = db.audit("user.disabled")
    assert disable_event["details"] == {"revoked_count": 1}

    # The disabled user's live session stops working immediately.
    restore_cookies(client, erin_cookies)
    assert client.get("/api/v1/auth/me").status_code == 401
    assert login(client, "erin").status_code == 401

    restore_cookies(client, admin_cookies)
    enabled = client.patch(
        f"/api/v1/admin/users/{target}", json={"is_active": True}, headers=csrf(client)
    )
    assert enabled.json()["is_active"] is True
    assert len(db.audit("user.enabled")) == 1


def test_admin_cannot_demote_or_disable_themselves(client: TestClient, admin: Any) -> None:
    for body in ({"role": "viewer"}, {"is_active": False}):
        response = client.patch(f"/api/v1/admin/users/{admin}", json=body, headers=csrf(client))
        assert response.status_code == 409


def test_last_admin_cannot_be_removed(db: Database, make_user: Callable[..., Any]) -> None:
    # Through the API the acting admin always remains, so this guard is
    # defence in depth for system actors (e.g. future CLI commands).
    only_admin = make_user("root", Role.ADMIN)

    async def demote() -> None:
        try:
            async with get_sessionmaker()() as session:
                await update_user(
                    session,
                    build_audit_service("cli"),
                    actor=SYSTEM_ACTOR,
                    user_id=only_admin,
                    role=Role.VIEWER,
                )
        finally:
            await dispose_engine()

    with pytest.raises(Conflict, match="active admin"):
        run(demote())
    assert db.audit("user.role.changed") == []


def test_admin_lists_and_revokes_sessions(
    client: TestClient, db: Database, admin: Any, make_user: Callable[..., Any]
) -> None:
    target = make_user("frank")
    admin_cookies = save_cookies(client)
    client.cookies.clear()
    login(client, "frank")
    frank_cookies = save_cookies(client)
    restore_cookies(client, admin_cookies)

    (session,) = client.get(f"/api/v1/admin/users/{target}/sessions").json()
    assert session["source_ip"] == "testclient"
    revoked = client.delete(f"/api/v1/admin/sessions/{session['id']}", headers=csrf(client))

    assert revoked.status_code == 204
    (event,) = db.audit("auth.session.revoked")
    assert event["reason"] == "admin_revoked"
    assert event["target"] == "frank"
    assert event["username"] == "root"
    restore_cookies(client, frank_cookies)
    assert client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
def test_rbac_denials_are_audited_on_the_real_auth_path(
    client: TestClient, db: Database, make_user: Callable[..., Any], role: Role
) -> None:
    make_user("grace", role)
    login(client, "grace")

    assert client.get("/api/v1/admin/users").status_code == 403
    assert client.post("/api/v1/admin/audit/verify", headers=csrf(client)).status_code == 403
    assert client.get("/api/v1/tools").status_code == 200  # viewer and up

    denials = db.audit("auth.access.denied")
    assert [d["target"] for d in denials] == [
        "GET /api/v1/admin/users",
        "POST /api/v1/admin/audit/verify",
    ]
    assert all(d["username"] == "grace" and d["outcome"] == "DENIED" for d in denials)


def test_audit_listing_filters_and_paginates(client: TestClient, db: Database, admin: Any) -> None:
    for _ in range(3):
        login(client, "root", "wrong-password-xyz")
    login(client, "root")

    page = client.get("/api/v1/admin/audit", params={"limit": 2}).json()
    assert len(page["events"]) == 2
    assert page["events"][0]["id"] > page["events"][1]["id"]  # newest first
    older = client.get(
        "/api/v1/admin/audit", params={"limit": 50, "before_id": page["next_before_id"]}
    ).json()
    assert all(e["id"] < page["events"][-1]["id"] for e in older["events"])

    failures = client.get(
        "/api/v1/admin/audit", params={"action": "auth.login.failure", "security_only": True}
    ).json()["events"]
    assert len(failures) == 3
    assert client.get("/api/v1/admin/audit", params={"action": "nope"}).status_code == 422


def test_cli_creates_first_admin_with_system_audit(db: Database) -> None:
    username = run(cli.create_admin("Admin.One", PASSWORD))

    assert username == "admin.one"
    (user,) = db.execute("SELECT role FROM users WHERE username = 'admin.one'")
    assert user["role"] == "admin"
    (event,) = db.audit("user.created")
    assert event["actor_type"] == "system"
    assert event["service"] == "cli"
    assert event["user_id"] is None
    assert event["target"] == "admin.one"


def test_cli_password_stdin_and_policy(
    db: Database, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("password1234\n"))
    with pytest.raises(SystemExit, match="too common"):
        cli.main(["create-admin", "--username", "weak", "--password-stdin"])

    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "--username", "strong", "--password-stdin"]) == 0
    assert "created" in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "--username", "strong", "--password-stdin"]) == 1
