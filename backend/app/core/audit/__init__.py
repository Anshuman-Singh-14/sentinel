"""Tamper-evident audit trail: who did what, to which target, when, from where."""

from app.config import get_settings
from app.core.audit.actions import ActorType, AuditAction, Outcome
from app.core.audit.alerts import (
    DbAlertSink,
    FailedLoginBurstRule,
    IntegrityFailureRule,
    LogAlertSink,
    RefreshTokenReuseRule,
)
from app.core.audit.context import Actor
from app.core.audit.service import AuditService, RecordedEvent
from app.db.session import get_sessionmaker

__all__ = [
    "Actor",
    "ActorType",
    "AuditAction",
    "AuditService",
    "Outcome",
    "RecordedEvent",
    "build_audit_service",
    "get_audit_service",
]


def build_audit_service(service: str) -> AuditService:
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    return AuditService(
        sessionmaker,
        service=service,
        rules=(
            FailedLoginBurstRule(
                threshold=settings.alert_failed_login_threshold,
                window_minutes=settings.alert_window_minutes,
            ),
            IntegrityFailureRule(),
            RefreshTokenReuseRule(),
        ),
        sinks=(LogAlertSink(), DbAlertSink(sessionmaker)),
    )


def get_audit_service() -> AuditService:
    """FastAPI dependency.

    Built per request (it is a few small objects) rather than cached, so it
    always uses the current engine, even after the engine is disposed and
    recreated (app restart in tests, Celery fork in workers).
    """
    return build_audit_service("api")
