"""Security alerting hooks, v1 (03-logging-audit.md section 7).

Rules look at each newly committed audit event and may raise an ``Alert``.
Sinks deliver alerts. v1 ships a log sink (WARNING line) and a database sink
(feeds the dashboard badge). Email, webhook or Slack sinks only need to
implement ``AlertSink.emit``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit.actions import AuditAction
from app.core.logging import get_logger
from app.db.models import AuditEvent, SecurityAlert

if TYPE_CHECKING:
    from app.core.audit.service import RecordedEvent

logger = get_logger("sentinel.alerts")


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str  # "MEDIUM" | "HIGH" | "CRITICAL"
    message: str
    audit_event_id: Any = None
    details: dict[str, Any] = field(default_factory=dict)


class AlertRule(Protocol):
    name: str

    async def evaluate(self, event: RecordedEvent, session: AsyncSession) -> Alert | None: ...


class AlertSink(Protocol):
    async def emit(self, alert: Alert) -> None: ...


class FailedLoginBurstRule:
    """N failed logins for one username, or from one IP, within T minutes.

    Fires when the count reaches the threshold and again at every further
    multiple of it, so an ongoing attack keeps alerting without one alert per
    attempt.
    """

    name = "failed_login_burst"

    def __init__(self, *, threshold: int, window_minutes: int) -> None:
        self._threshold = threshold
        self._window = timedelta(minutes=window_minutes)

    async def evaluate(self, event: RecordedEvent, session: AsyncSession) -> Alert | None:
        if event.action != AuditAction.AUTH_LOGIN_FAILURE:
            return None
        since = event.occurred_at - self._window
        checks = (
            ("username", AuditEvent.username, event.actor.username),
            ("source_ip", AuditEvent.source_ip, event.actor.source_ip),
        )
        for dimension, column, value in checks:
            if not value:
                continue
            count = await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.action == str(AuditAction.AUTH_LOGIN_FAILURE),
                    AuditEvent.occurred_at >= since,
                    column == value,
                )
            )
            if count and count % self._threshold == 0:
                return Alert(
                    rule=self.name,
                    severity="HIGH",
                    message=(
                        f"{count} failed logins for {dimension} {value!r} "
                        f"in the last {int(self._window.total_seconds() // 60)} minutes."
                    ),
                    audit_event_id=event.event_id,
                    details={"dimension": dimension, "value": value, "count": count},
                )
        return None


class IntegrityFailureRule:
    name = "audit_integrity_failure"

    async def evaluate(self, event: RecordedEvent, session: AsyncSession) -> Alert | None:
        if event.action != AuditAction.AUDIT_INTEGRITY_FAILED:
            return None
        return Alert(
            rule=self.name,
            severity="CRITICAL",
            message=(
                "Audit trail integrity verification failed: the log may have been tampered with."
            ),
            audit_event_id=event.event_id,
            details=dict(event.details),
        )


class RefreshTokenReuseRule:
    """A rotated-out refresh token came back: the session's token was likely stolen."""

    name = "refresh_token_reuse"

    async def evaluate(self, event: RecordedEvent, session: AsyncSession) -> Alert | None:
        if (
            event.action != AuditAction.AUTH_SESSION_REVOKED
            or event.reason != "refresh_token_reuse"
        ):
            return None
        return Alert(
            rule=self.name,
            severity="HIGH",
            message=f"Refresh token reuse detected for user {event.actor.username!r}; "
            "the session was revoked.",
            audit_event_id=event.event_id,
            details={"username": event.actor.username},
        )


class LogAlertSink:
    async def emit(self, alert: Alert) -> None:
        logger.warning(
            "security.alert",
            rule=alert.rule,
            severity=alert.severity,
            alert_message=alert.message,
            audit_event_id=str(alert.audit_event_id) if alert.audit_event_id else None,
        )


class DbAlertSink:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def emit(self, alert: Alert) -> None:
        async with self._sessionmaker() as session, session.begin():
            session.add(
                SecurityAlert(
                    rule=alert.rule,
                    severity=alert.severity,
                    message=alert.message[:512],
                    details=alert.details,
                    audit_event_id=alert.audit_event_id,
                )
            )
