"""The audit hash chain detects modification, deletion, insertion and reordering.

These are pure-function tests. tests/integration/test_audit_trail.py proves the
same against real rows in Postgres.
"""

import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from app.core.audit.actions import AuditAction, Outcome, is_security_event
from app.core.audit.chain import (
    GENESIS_HASH,
    HASHED_FIELDS,
    ChainVerifier,
    canonical_json,
    compute_row_hash,
)


def _event(n: int) -> dict[str, Any]:
    return {
        "event_id": uuid.UUID(int=n),
        "occurred_at": datetime(2026, 10, 2, 12, 0, tzinfo=UTC) + timedelta(seconds=n),
        "actor_type": "user",
        "user_id": uuid.UUID(int=1000 + n),
        "username": f"user{n}",
        "role": "analyst",
        "session_id": None,
        "source_ip": "203.0.113.7",
        "user_agent": "pytest",
        "service": "api",
        "hostname": "host",
        "process_user": "sentinel",
        "action": "auth.login.success",
        "resource_type": None,
        "resource_id": None,
        "target": None,
        "outcome": "SUCCESS",
        "reason": None,
        "details": {"n": n, "nested": {"b": 2, "a": [1, "x"]}},
        "request_id": f"req-{n}",
        "is_security_event": False,
    }


def _chain(length: int) -> list[dict[str, Any]]:
    rows, prev = [], GENESIS_HASH
    for n in range(1, length + 1):
        event = _event(n)
        row = {**event, "id": n, "prev_hash": prev, "row_hash": compute_row_hash(prev, event)}
        rows.append(row)
        prev = row["row_hash"]
    return rows


def _verify(rows: list[dict[str, Any]]) -> Any:
    verifier = ChainVerifier()
    for row in rows:
        verifier.feed(row)
    return verifier.result()


def test_intact_chain_verifies() -> None:
    rows = _chain(5)
    result = _verify(rows)

    assert result.ok
    assert result.checked == 5
    assert result.head_hash == rows[-1]["row_hash"]
    assert result.first_broken_id is None


def test_empty_chain_is_valid() -> None:
    result = _verify([])
    assert result.ok and result.checked == 0 and result.head_hash == GENESIS_HASH


@pytest.mark.parametrize("field", ["username", "outcome", "details", "occurred_at", "target"])
def test_modified_row_is_detected(field: str) -> None:
    rows = _chain(5)
    original = rows[2][field]
    if field == "details":
        rows[2][field] = {"tampered": True}
    elif field == "occurred_at":
        rows[2][field] = original + timedelta(microseconds=1)
    else:
        rows[2][field] = "tampered"

    result = _verify(rows)
    assert not result.ok
    assert result.first_broken_id == 3
    assert result.reason == "row_hash_mismatch"
    assert result.checked == 2


def test_deleted_row_is_detected() -> None:
    rows = _chain(5)
    del rows[2]

    result = _verify(rows)
    assert not result.ok
    assert result.first_broken_id == 4
    assert result.reason == "prev_hash_mismatch"


def test_reordered_rows_are_detected() -> None:
    rows = _chain(5)
    rows[1], rows[2] = rows[2], rows[1]

    result = _verify(rows)
    assert not result.ok
    assert result.first_broken_id == 3


def test_recomputing_one_hash_still_breaks_the_next_link() -> None:
    # An attacker who edits a row and recomputes its hash must rewrite every
    # later row too; fixing just one leaves the next link broken.
    rows = _chain(5)
    rows[2]["outcome"] = "FAILURE"
    rows[2]["row_hash"] = compute_row_hash(rows[2]["prev_hash"], rows[2])

    result = _verify(rows)
    assert result.first_broken_id == 4
    assert result.reason == "prev_hash_mismatch"


def test_canonical_json_is_order_independent_and_compact() -> None:
    event = _event(1)
    reordered = dict(reversed(list(event.items())))
    reordered["details"] = {"nested": {"a": [1, "x"], "b": 2}, "n": 1}

    assert canonical_json(event) == canonical_json(reordered)
    assert b" " not in canonical_json({"details": {"a": 1}})


def test_canonical_json_normalises_timezones() -> None:
    utc = _event(1)
    shifted = {**utc, "occurred_at": utc["occurred_at"].astimezone(timezone(timedelta(hours=5)))}
    assert canonical_json(utc) == canonical_json(shifted)


def test_naive_timestamps_are_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json({**_event(1), "occurred_at": datetime(2026, 1, 1)})


def test_hash_covers_every_column_but_id_and_hashes() -> None:
    assert "id" not in HASHED_FIELDS
    assert "prev_hash" not in HASHED_FIELDS
    assert "row_hash" not in HASHED_FIELDS
    assert len(HASHED_FIELDS) == 21


def test_security_event_classification() -> None:
    assert is_security_event(AuditAction.AUTH_LOGIN_FAILURE, Outcome.FAILURE)
    assert is_security_event(AuditAction.AUTH_ACCESS_DENIED, Outcome.DENIED)
    assert is_security_event(AuditAction.AUTH_TOKEN_REFRESH, Outcome.DENIED)
    assert not is_security_event(AuditAction.AUTH_LOGIN_SUCCESS, Outcome.SUCCESS)
    assert not is_security_event(AuditAction.AUTH_LOGOUT, Outcome.SUCCESS)
