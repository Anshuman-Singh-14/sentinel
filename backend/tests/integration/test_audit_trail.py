"""Phase 2 acceptance: the audit table is append-only and tampering is detected.

* UPDATE/DELETE/TRUNCATE are refused for the app role (grants) and for the
  owner (trigger).
* The verify endpoint finds the first broken link after a manual edit or
  deletion, records ``audit.integrity.failed`` and raises a critical alert.
"""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError

from app.core.audit import Actor, ActorType, AuditAction, Outcome, build_audit_service
from app.core.auth.roles import Role
from app.db.session import dispose_engine
from tests.integration.conftest import Database, csrf, login, run


@pytest.fixture
def seeded(db: Database, make_user: Callable[..., Any], client: TestClient) -> TestClient:
    """An admin session plus a handful of audit events."""
    make_user("root", Role.ADMIN)
    login(client, "root", "wrong-password-xyz")
    login(client, "root", "wrong-password-xyz")
    assert login(client, "root").status_code == 200
    return client


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET outcome = 'SUCCESS'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
@pytest.mark.parametrize("role", ["app", "owner"])
def test_audit_rows_cannot_be_changed(
    seeded: TestClient, db: Database, sql: str, role: str
) -> None:
    with pytest.raises(DBAPIError) as exc_info:
        db.execute(sql, role=role)

    message = str(exc_info.value.orig)
    # The app role is stopped by its grants; the owner by the trigger.
    expected = "permission denied" if role == "app" else "append-only"
    assert expected in message
    assert len(db.audit()) == 3


def test_app_role_can_insert_and_select_only(db: Database) -> None:
    (row,) = db.execute(
        "SELECT has_table_privilege('sentinel_app', 'audit_events', 'INSERT') AS ins,"
        " has_table_privilege('sentinel_app', 'audit_events', 'SELECT') AS sel,"
        " has_table_privilege('sentinel_app', 'audit_events', 'UPDATE') AS upd,"
        " has_table_privilege('sentinel_app', 'audit_events', 'DELETE') AS del,"
        " has_table_privilege('sentinel_app', 'audit_events', 'TRUNCATE') AS trunc",
        role="owner",
    )
    assert dict(row) == {"ins": True, "sel": True, "upd": False, "del": False, "trunc": False}


def test_intact_chain_verifies_and_is_audited(seeded: TestClient, db: Database) -> None:
    response = seeded.post("/api/v1/admin/audit/verify", headers=csrf(seeded))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["checked"] == 3
    assert body["first_broken_id"] is None
    assert body["head_hash"] == db.audit()[2]["row_hash"]
    (event,) = db.audit("audit.integrity.verified")
    assert event["details"]["checked"] == 3
    assert event["is_security_event"] is False


def test_modified_row_is_detected_and_alerts(seeded: TestClient, db: Database) -> None:
    db.tamper("UPDATE audit_events SET reason = 'nothing to see' WHERE id = 2")

    body = seeded.post("/api/v1/admin/audit/verify", headers=csrf(seeded)).json()

    assert body["ok"] is False
    assert body["first_broken_id"] == 2
    assert body["reason"] == "row_hash_mismatch"
    assert body["checked"] == 1
    (event,) = db.audit("audit.integrity.failed")
    assert event["is_security_event"] is True
    assert event["details"]["first_broken_id"] == 2
    (alert,) = db.alerts()
    assert alert["rule"] == "audit_integrity_failure"
    assert alert["severity"] == "CRITICAL"


def test_deleted_row_is_detected(seeded: TestClient, db: Database) -> None:
    db.tamper("DELETE FROM audit_events WHERE id = 2")

    body = seeded.post("/api/v1/admin/audit/verify", headers=csrf(seeded)).json()

    assert body["ok"] is False
    assert body["first_broken_id"] == 3
    assert body["reason"] == "prev_hash_mismatch"


def test_concurrent_writers_keep_the_chain_linear(db: Database) -> None:
    async def write_many() -> None:
        audit = build_audit_service("api")
        actor = Actor(actor_type=ActorType.SYSTEM)
        try:
            await asyncio.gather(
                *(
                    audit.record(AuditAction.AUDIT_EXPORTED, actor=actor, outcome=Outcome.SUCCESS)
                    for _ in range(25)
                )
            )
            result = await audit.verify_chain()
        finally:
            await dispose_engine()
        assert result.ok, result
        assert result.checked == 25

    run(write_many())
    rows = db.audit()
    assert len({row["prev_hash"] for row in rows}) == 25  # no two rows share a parent


def test_details_are_redacted_before_hashing_and_storage(db: Database) -> None:
    async def write() -> None:
        audit = build_audit_service("api")
        try:
            await audit.record(
                AuditAction.PROVIDER_CONFIG_CHANGED,
                actor=Actor(actor_type=ActorType.SYSTEM),
                outcome=Outcome.SUCCESS,
                details={
                    "provider": "virustotal",
                    "api_key": "dummy-api-key",
                    "note": "header was Bearer abc.def.ghi",
                    "nul": "a\x00b",
                },
            )
        finally:
            await dispose_engine()

    run(write())
    (event,) = db.audit()
    assert event["details"]["provider"] == "virustotal"
    assert event["details"]["api_key"] == "[REDACTED]"
    assert "abc.def.ghi" not in event["details"]["note"]
    assert event["details"]["nul"] == "ab"


def test_failed_login_burst_raises_an_alert(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("alice")
    for _ in range(5):  # ALERT_FAILED_LOGIN_THRESHOLD default
        login(client, "alice", "wrong-password-xyz")

    alerts = db.alerts()
    assert [a["rule"] for a in alerts] == ["failed_login_burst"]
    assert alerts[0]["details"]["count"] == 5
    assert alerts[0]["severity"] == "HIGH"

    listed = db.execute("SELECT count(*) AS n FROM security_alerts WHERE acknowledged_at IS NULL")
    assert listed[0]["n"] == 1
