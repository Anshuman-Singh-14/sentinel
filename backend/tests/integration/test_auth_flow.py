"""Login, lockout, rate limiting, refresh rotation, logout and password change.

Phase 2 acceptance: every auth action produces an audit event.
"""

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from app.core.auth.roles import Role
from app.core.auth.tokens import hash_token
from tests.integration.conftest import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    ORIGIN,
    PASSWORD,
    REFRESH_COOKIE,
    Database,
    csrf,
    login,
    restore_cookies,
    save_cookies,
)

NEW_PASSWORD = "copper-lantern-58-meadow"


def _error_without_request_id(response: Any) -> dict[str, Any]:
    body: dict[str, Any] = response.json()["error"]
    body.pop("request_id")
    return body


def test_login_success_sets_cookies_and_audits(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    user_id = make_user("alice", Role.ANALYST)

    response = login(client, "Alice")  # usernames are case-insensitive

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "analyst"
    for name in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE):
        assert client.cookies.get(name), name

    (event,) = db.audit("auth.login.success")
    assert event["user_id"] == user_id
    assert event["username"] == "alice"
    assert event["role"] == "analyst"
    assert event["actor_type"] == "user"
    assert event["outcome"] == "SUCCESS"
    assert str(event["session_id"]) == body["session_id"]
    assert event["source_ip"] == "testclient"
    assert event["service"] == "api"
    assert event["request_id"] == response.headers["X-Request-ID"]
    assert event["is_security_event"] is False

    # Only digests are stored, never the tokens themselves.
    (session,) = db.execute("SELECT * FROM sessions")
    access = client.cookies.get(ACCESS_COOKIE)
    assert session["access_token_hash"] == hash_token(access or "")
    assert access not in str(dict(session))


def test_me_requires_a_session(client: TestClient, make_user: Callable[..., Any]) -> None:
    assert client.get("/api/v1/auth/me").status_code == 401
    make_user("alice")
    login(client, "alice")
    assert client.get("/api/v1/auth/me").json()["username"] == "alice"


def test_login_failures_are_indistinguishable_but_audited_precisely(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    make_user("bob", is_active=False)

    wrong = login(client, "alice", "not-the-password-1")
    unknown = login(client, "mallory", PASSWORD)
    disabled = login(client, "bob", PASSWORD)

    for response in (wrong, unknown, disabled):
        assert response.status_code == 401
    assert (
        _error_without_request_id(wrong)
        == _error_without_request_id(unknown)
        == _error_without_request_id(disabled)
    )
    assert _error_without_request_id(wrong)["code"] == "invalid_credentials"

    events = db.audit("auth.login.failure")
    assert [e["reason"] for e in events] == ["bad_password", "unknown_user", "account_disabled"]
    assert all(e["is_security_event"] for e in events)
    assert all(e["outcome"] == "FAILURE" for e in events)
    assert [e["username"] for e in events] == ["alice", "mallory", "bob"]
    assert events[0]["details"] == {"failed_count": 1}
    # The attempted password never reaches the audit trail.
    assert "not-the-password-1" not in str([dict(e) for e in events])


def test_lockout_after_repeated_failures(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    for _ in range(5):  # LOGIN_MAX_FAILURES default
        assert login(client, "alice", "wrong-password-xyz").status_code == 401

    (lockout,) = db.audit("auth.lockout")
    assert lockout["details"] == {"failed_count": 5, "locked_seconds": 60}
    assert lockout["is_security_event"] is True

    # Locked: even the right password is refused, for a recorded reason.
    assert login(client, "alice").status_code == 401
    assert db.audit("auth.login.failure")[-1]["reason"] == "account_locked"

    # Once the lock expires the right password works and resets the counter.
    db.execute("UPDATE users SET locked_until = now() - interval '1 second'")
    assert login(client, "alice").status_code == 200
    (user,) = db.execute("SELECT failed_login_count, locked_until FROM users")
    assert user["failed_login_count"] == 0
    assert user["locked_until"] is None


def test_lockout_backoff_doubles(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    for _ in range(5):
        login(client, "alice", "wrong-password-xyz")
    db.execute("UPDATE users SET locked_until = now() - interval '1 second'")
    login(client, "alice", "wrong-password-xyz")

    assert [e["details"]["locked_seconds"] for e in db.audit("auth.lockout")] == [60, 120]


def test_per_ip_rate_limit_blocks_password_spraying(client: TestClient, db: Database) -> None:
    statuses = [login(client, f"user{n}", PASSWORD).status_code for n in range(11)]

    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429
    limited = login(client, "user99", PASSWORD)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    denied = [e for e in db.audit("auth.login.failure") if e["reason"] == "rate_limited"]
    assert denied and all(e["outcome"] == "DENIED" for e in denied)


def test_login_rejects_foreign_origin(client: TestClient, make_user: Callable[..., Any]) -> None:
    make_user("alice")
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_login_rejects_unknown_fields_and_oversized_input(client: TestClient, db: Database) -> None:
    extra = client.post(
        "/api/v1/auth/login", json={"username": "a", "password": "b", "role": "admin"}
    )
    huge = client.post("/api/v1/auth/login", json={"username": "a", "password": "x" * 5000})
    assert extra.status_code == 422
    assert huge.status_code == 422
    assert "x" * 100 not in huge.text  # validation errors never echo input


def test_refresh_rotates_every_token(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")
    old = {name: client.cookies.get(name) for name in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE)}

    response = client.post("/api/v1/auth/refresh", headers={"Origin": ORIGIN})

    assert response.status_code == 200
    for name, value in old.items():
        assert client.cookies.get(name) != value, name
    (event,) = db.audit("auth.token.refresh")
    assert event["outcome"] == "SUCCESS"
    assert event["username"] == "alice"

    # The superseded access token no longer authenticates.
    current = save_cookies(client)
    client.cookies.clear()
    for cookie in current:
        if cookie.name == ACCESS_COOKIE:
            cookie.value = old[ACCESS_COOKIE]
        client.cookies.jar.set_cookie(cookie)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_refresh_token_reuse_revokes_the_session_and_alerts(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")
    stolen = save_cookies(client)
    assert client.post("/api/v1/auth/refresh").status_code == 200  # legitimate rotation
    legitimate = save_cookies(client)

    restore_cookies(client, stolen)  # the attacker replays the old refresh token
    assert client.post("/api/v1/auth/refresh").status_code == 401
    restore_cookies(client, legitimate)

    (revoked,) = db.audit("auth.session.revoked")
    assert revoked["reason"] == "refresh_token_reuse"
    assert revoked["username"] == "alice"
    assert revoked["actor_type"] == "anonymous"
    assert revoked["is_security_event"] is True
    (session,) = db.execute("SELECT revoked_reason FROM sessions")
    assert session["revoked_reason"] == "refresh_token_reuse"
    assert [a["rule"] for a in db.alerts()] == ["refresh_token_reuse"]

    # The legitimate holder's newer tokens die with the session.
    assert client.post("/api/v1/auth/refresh").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    assert db.audit("auth.token.refresh")[-1]["reason"] == "session_revoked"


def test_refresh_without_cookie_is_audited(client: TestClient, db: Database) -> None:
    assert client.post("/api/v1/auth/refresh").status_code == 401
    (event,) = db.audit("auth.token.refresh")
    assert event["reason"] == "missing_token"
    assert event["outcome"] == "FAILURE"


def test_logout_revokes_session_and_clears_cookies(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")
    before = save_cookies(client)

    response = client.post("/api/v1/auth/logout", headers=csrf(client))

    assert response.status_code == 204
    assert client.cookies.get(ACCESS_COOKIE) is None
    (event,) = db.audit("auth.logout")
    assert event["username"] == "alice"
    (session,) = db.execute("SELECT revoked_reason FROM sessions")
    assert session["revoked_reason"] == "logout"
    restore_cookies(client, before)  # replaying the old cookies does not work
    assert client.get("/api/v1/auth/me").status_code == 401


def test_logout_requires_csrf(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")
    assert client.post("/api/v1/auth/logout").status_code == 403
    assert db.audit("auth.logout") == []
    (denied,) = db.audit("auth.access.denied")
    assert denied["reason"] == "csrf_token_missing"
    assert denied["username"] == "alice"


def test_state_change_without_csrf_token_is_denied_and_audited(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")

    response = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    (event,) = db.audit("auth.access.denied")
    assert event["reason"] == "csrf_token_missing"
    assert event["target"] == "POST /api/v1/auth/password"
    assert event["outcome"] == "DENIED"


def test_password_change_revokes_other_sessions(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")
    other_session = save_cookies(client)
    client.cookies.clear()
    login(client, "alice")
    this_session = save_cookies(client)

    response = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf(client),
    )

    assert response.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 200  # this session survives
    restore_cookies(client, other_session)
    assert client.get("/api/v1/auth/me").status_code == 401
    restore_cookies(client, this_session)
    (event,) = db.audit("user.password.changed")
    assert event["outcome"] == "SUCCESS"
    assert event["details"] == {"revoked_count": 1}
    assert login(client, "alice").status_code == 401
    assert login(client, "alice", NEW_PASSWORD).status_code == 200


def test_password_change_checks_current_and_policy(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice")

    wrong = client.post(
        "/api/v1/auth/password",
        json={"current_password": "not-it-at-all-1", "new_password": NEW_PASSWORD},
        headers=csrf(client),
    )
    weak = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "password1234"},
        headers=csrf(client),
    )

    assert wrong.status_code == 403
    assert weak.status_code == 422
    assert weak.json()["error"]["code"] == "password_policy"
    (event,) = db.audit("user.password.changed")
    assert event["outcome"] == "FAILURE"
    assert event["reason"] == "bad_current_password"


def test_every_auth_action_produces_an_audit_event(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    login(client, "alice", "wrong-password-xyz")
    login(client, "alice")
    client.post("/api/v1/auth/refresh")
    client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf(client),
    )
    client.post("/api/v1/auth/logout", headers=csrf(client))

    assert [e["action"] for e in db.audit()] == [
        "auth.login.failure",
        "auth.login.success",
        "auth.token.refresh",
        "user.password.changed",
        "auth.logout",
    ]
