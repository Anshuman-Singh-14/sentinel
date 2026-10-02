"""Hash chain for tamper-evident audit events. Pure functions, no I/O.

``row_hash = SHA-256(prev_hash || "|" || canonical_json(event))``

* ``canonical_json`` is deterministic: sorted keys, no whitespace, UTF-8,
  UTC timestamps with microseconds, UUIDs as strings. The same event always
  produces the same bytes, whether hashed at insert time or re-read later.
* The first row links to ``GENESIS_HASH``.
* Changing any field of a row breaks its ``row_hash``. Deleting or reordering
  rows breaks the next row's ``prev_hash`` link.

Limit (documented in ADR 0003): deleting rows from the *end* of the chain
leaves a valid shorter chain. ``ChainVerifier`` therefore reports the head
hash and row count, which can be anchored externally (e.g. copied into a
ticket or shipped to WORM storage) to detect truncation.
"""

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64

# Every column except the database-generated id and the two hash columns.
# The order is irrelevant (keys are sorted); the *set* is part of the format.
HASHED_FIELDS: tuple[str, ...] = (
    "event_id",
    "occurred_at",
    "actor_type",
    "user_id",
    "username",
    "role",
    "session_id",
    "source_ip",
    "user_agent",
    "service",
    "hostname",
    "process_user",
    "action",
    "resource_type",
    "resource_id",
    "target",
    "outcome",
    "reason",
    "details",
    "request_id",
    "is_security_event",
)


def _normalise(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("audit timestamps must be timezone-aware")
        # Fixed format with microseconds: Postgres timestamptz keeps exactly
        # microsecond precision, so the value round-trips unchanged.
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def canonical_json(event: Mapping[str, Any]) -> bytes:
    payload = {field: _normalise(event.get(field)) for field in HASHED_FIELDS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def compute_row_hash(prev_hash: str, event: Mapping[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(b"|")
    digest.update(canonical_json(event))
    return digest.hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    checked: int
    head_hash: str
    first_broken_id: int | None = None
    reason: str | None = None


class ChainVerifier:
    """Verifies rows fed in ascending ``id`` order, in as many batches as needed.

    Streaming keeps memory bounded however large the table grows.
    """

    def __init__(self) -> None:
        self._expected_prev = GENESIS_HASH
        self._checked = 0
        self._broken_id: int | None = None
        self._reason: str | None = None

    @property
    def broken(self) -> bool:
        return self._broken_id is not None

    def feed(self, row: Mapping[str, Any]) -> None:
        if self.broken:
            return
        row_id = int(row["id"])
        if row["prev_hash"] != self._expected_prev:
            # A row was deleted or reordered before this one (or this row's
            # link was edited).
            self._broken_id, self._reason = row_id, "prev_hash_mismatch"
            return
        if compute_row_hash(row["prev_hash"], row) != row["row_hash"]:
            # This row's content was modified after it was written.
            self._broken_id, self._reason = row_id, "row_hash_mismatch"
            return
        self._expected_prev = row["row_hash"]
        self._checked += 1

    def result(self) -> VerificationResult:
        return VerificationResult(
            ok=not self.broken,
            checked=self._checked,
            head_hash=self._expected_prev,
            first_broken_id=self._broken_id,
            reason=self._reason,
        )
