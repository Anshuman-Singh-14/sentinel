"""Writing and verifying the audit trail (03-logging-audit.md section 5).

Two write modes, chosen by the caller:

* ``record(..., session=s)`` joins the caller's transaction. The event and the
  change it describes commit or roll back together, so a change can never
  exist without its audit row (used for user creation, role changes...).
* ``record(...)`` without a session commits on its own short transaction. Used
  for failures and denials: the main action's transaction may roll back, but
  its audit row must still be written.

Either way, a failed audit write raises ``AuditUnavailable`` and the action
fails closed.

Chain linearity: every insert takes a transaction-scoped advisory lock before
reading the previous row's hash, so two concurrent writers can never both link
to the same predecessor. The lock is released at commit or rollback.
"""

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit.actions import AuditAction, Outcome, is_security_event
from app.core.audit.alerts import AlertRule, AlertSink
from app.core.audit.chain import GENESIS_HASH, ChainVerifier, VerificationResult, compute_row_hash
from app.core.audit.context import Actor, system_identity
from app.core.errors import AuditUnavailable
from app.core.ids import uuid7
from app.core.logging import get_logger
from app.core.logging.context import current_request_id
from app.core.logging.redaction import redact
from app.db.models import AuditEvent

logger = get_logger("sentinel.audit")

# Arbitrary constant identifying "the audit chain" lock. Any bigint works as
# long as nothing else in the database uses the same key.
AUDIT_CHAIN_LOCK_KEY = 0x5E47_1E1A_0D17
# Audit details are capped harder than log fields: they are stored for a year.
DETAILS_MAX_FIELD_LENGTH = 1024
VERIFY_BATCH_SIZE = 1000

# Column lengths, mirrored from the model, for defensive truncation.
_LIMITS = {
    "username": 64,
    "role": 16,
    "source_ip": 64,
    "user_agent": 512,
    "resource_type": 64,
    "resource_id": 128,
    "target": 512,
    "reason": 256,
    "request_id": 64,
}


def _clean(field: str, value: str | None) -> str | None:
    if value is None:
        return None
    # Postgres text and JSONB reject NUL bytes; strip them rather than fail.
    cleaned = value.replace("\x00", "")
    limit = _LIMITS.get(field)
    return cleaned[:limit] if limit else cleaned


def _sanitise_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Redact, then round-trip through JSON.

    The round trip guarantees that what is hashed is exactly what JSONB will
    store and return (no tuples, datetimes or other non-JSON types).
    """
    redacted = redact(dict(details or {}), max_length=DETAILS_MAX_FIELD_LENGTH)
    encoded = json.dumps(redacted, default=str, allow_nan=False).replace("\\u0000", "")
    result = json.loads(encoded)
    return result if isinstance(result, dict) else {}


@dataclass(frozen=True)
class RecordedEvent:
    """A committed (or about-to-commit) audit event, as passed to alert rules."""

    id: int
    event_id: uuid.UUID
    occurred_at: datetime
    action: str
    outcome: str
    actor: Actor
    target: str | None
    reason: str | None
    details: dict[str, Any]
    is_security_event: bool


class AuditService:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        service: str,
        rules: Sequence[AlertRule] = (),
        sinks: Sequence[AlertSink] = (),
    ) -> None:
        self._sessionmaker = sessionmaker
        self._identity = system_identity(service)
        self._rules = tuple(rules)
        self._sinks = tuple(sinks)

    async def record(
        self,
        action: AuditAction,
        *,
        actor: Actor,
        outcome: Outcome,
        resource_type: str | None = None,
        resource_id: str | None = None,
        target: str | None = None,
        reason: str | None = None,
        details: Mapping[str, Any] | None = None,
        security_event: bool | None = None,
        session: AsyncSession | None = None,
    ) -> RecordedEvent:
        args = (action, actor, outcome, resource_type, resource_id, target, reason, details)
        try:
            if session is not None:
                # Joined transaction: the caller commits. Alert rules are not
                # evaluated, because the transaction might still roll back;
                # the caller calls ``after_commit(event)`` once it has committed.
                return await self._insert(session, *args, security_event)
            async with self._sessionmaker() as own, own.begin():
                event = await self._insert(own, *args, security_event)
        except SQLAlchemyError as exc:
            # Never let an unrecorded security action proceed (fail closed).
            logger.error("audit.write_failed", action=str(action), error=type(exc).__name__)
            raise AuditUnavailable from exc

        await self._evaluate_rules(event)
        return event

    async def _insert(
        self,
        session: AsyncSession,
        action: AuditAction,
        actor: Actor,
        outcome: Outcome,
        resource_type: str | None,
        resource_id: str | None,
        target: str | None,
        reason: str | None,
        details: Mapping[str, Any] | None,
        security_event: bool | None,
    ) -> RecordedEvent:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_CHAIN_LOCK_KEY}
        )
        prev_hash = await session.scalar(
            select(AuditEvent.row_hash).order_by(AuditEvent.id.desc()).limit(1)
        )
        flagged = is_security_event(action, outcome) if security_event is None else security_event
        values: dict[str, Any] = {
            "event_id": uuid7(),
            # Truncated to microseconds is implicit: datetime has no finer unit.
            "occurred_at": datetime.now(UTC),
            "actor_type": str(actor.actor_type),
            "user_id": actor.user_id,
            "username": _clean("username", actor.username),
            "role": _clean("role", actor.role),
            "session_id": actor.session_id,
            "source_ip": _clean("source_ip", actor.source_ip),
            "user_agent": _clean("user_agent", actor.user_agent),
            "service": self._identity.service,
            "hostname": self._identity.hostname[:255],
            "process_user": self._identity.process_user[:64],
            "action": str(action),
            "resource_type": _clean("resource_type", resource_type),
            "resource_id": _clean("resource_id", resource_id),
            "target": _clean("target", target),
            "outcome": str(outcome),
            "reason": _clean("reason", reason),
            "details": _sanitise_details(details),
            "request_id": _clean("request_id", current_request_id()),
            "is_security_event": flagged,
        }
        values["prev_hash"] = prev_hash or GENESIS_HASH
        values["row_hash"] = compute_row_hash(values["prev_hash"], values)

        row = AuditEvent(**values)
        session.add(row)
        await session.flush()

        log = logger.warning if flagged else logger.info
        log(
            "audit.event",
            action=values["action"],
            outcome=values["outcome"],
            audit_event_id=str(values["event_id"]),
            security_event=flagged,
        )
        return RecordedEvent(
            id=row.id,
            event_id=values["event_id"],
            occurred_at=values["occurred_at"],
            action=values["action"],
            outcome=values["outcome"],
            actor=actor,
            target=values["target"],
            reason=values["reason"],
            details=values["details"],
            is_security_event=flagged,
        )

    async def after_commit(self, event: RecordedEvent) -> None:
        """Run alert rules for an event recorded in a joined transaction."""
        await self._evaluate_rules(event)

    async def _evaluate_rules(self, event: RecordedEvent) -> None:
        if not self._rules:
            return
        try:
            async with self._sessionmaker() as session:
                for rule in self._rules:
                    alert = await rule.evaluate(event, session)
                    if alert is None:
                        continue
                    for sink in self._sinks:
                        await sink.emit(alert)
        # Alerting is best effort: the audit row is already committed, and a
        # broken alert sink must not turn a recorded action into an error.
        except Exception as exc:  # noqa: BLE001
            logger.error("audit.alerting_failed", action=event.action, error=type(exc).__name__)

    async def verify_chain(self) -> VerificationResult:
        """Recompute the whole chain in batches (keyset pagination by id)."""
        verifier = ChainVerifier()
        columns = [getattr(AuditEvent, name) for name in _VERIFY_COLUMNS]
        last_id = 0
        async with self._sessionmaker() as session:
            while not verifier.broken:
                result = await session.execute(
                    select(*columns)
                    .where(AuditEvent.id > last_id)
                    .order_by(AuditEvent.id)
                    .limit(VERIFY_BATCH_SIZE)
                )
                rows = result.mappings().all()
                if not rows:
                    break
                for row in rows:
                    verifier.feed(dict(row))
                last_id = rows[-1]["id"]
        return verifier.result()


_VERIFY_COLUMNS = (
    "id",
    "prev_hash",
    "row_hash",
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
