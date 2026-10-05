"""Audit vocabulary: stable action names, outcomes and actor types.

Action strings are part of the audit record and of the hash chain, so they
must never be renamed. Add new members; never change existing values.
"""

from enum import StrEnum


class AuditAction(StrEnum):
    # Authentication and sessions
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOCKOUT = "auth.lockout"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REFRESH = "auth.token.refresh"  # noqa: S105  (an action name, not a secret)
    AUTH_SESSION_REVOKED = "auth.session.revoked"
    # Not in the original taxonomy: gives authorization probing (403s, CSRF
    # failures) an audit trail. Added in Phase 2, see ADR 0003.
    AUTH_ACCESS_DENIED = "auth.access.denied"

    # User administration
    USER_CREATED = "user.created"
    USER_ROLE_CHANGED = "user.role.changed"
    USER_DISABLED = "user.disabled"
    USER_ENABLED = "user.enabled"
    USER_PASSWORD_CHANGED = "user.password.changed"  # noqa: S105  (action name)

    # Tool runs (Phase 5+)
    TOOL_RUN_REQUESTED = "tool.run.requested"
    TOOL_RUN_DENIED_SCOPE = "tool.run.denied_scope"
    TOOL_RUN_STARTED = "tool.run.started"
    TOOL_RUN_COMPLETED = "tool.run.completed"
    TOOL_RUN_FAILED = "tool.run.failed"
    TOOL_RUN_CANCELLED = "tool.run.cancelled"

    # Playbooks (Phase 12)
    PLAYBOOK_RUN_REQUESTED = "playbook.run.requested"
    PLAYBOOK_RUN_STARTED = "playbook.run.started"
    PLAYBOOK_RUN_COMPLETED = "playbook.run.completed"
    PLAYBOOK_RUN_FAILED = "playbook.run.failed"
    PLAYBOOK_RUN_CANCELLED = "playbook.run.cancelled"

    # Scope and providers (Phases 6, 8)
    SCOPE_POLICY_CHANGED = "scope.policy.changed"
    SCOPE_AUTHORIZATION_ACKNOWLEDGED = "scope.authorization.acknowledged"
    PROVIDER_CONFIG_CHANGED = "provider.config.changed"

    # FIM and log analysis (Phases 10, 11)
    FIM_BASELINE_CREATED = "fim.baseline.created"
    FIM_BASELINE_DELETED = "fim.baseline.deleted"
    FIM_CHECK_COMPLETED = "fim.check.completed"
    # Not in the original taxonomy: schedule changes on a baseline (ADR 0015).
    FIM_BASELINE_UPDATED = "fim.baseline.updated"
    LOG_ANALYSIS_REQUESTED = "log.analysis.requested"

    # Reports (Phase 13)
    REPORT_GENERATED = "report.generated"
    REPORT_EXPORTED = "report.exported"
    REPORT_DOWNLOADED = "report.downloaded"

    # Audit trail itself
    AUDIT_EXPORTED = "audit.exported"
    AUDIT_INTEGRITY_VERIFIED = "audit.integrity.verified"
    AUDIT_INTEGRITY_FAILED = "audit.integrity.failed"


class Outcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class ActorType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


# Always flagged as security events (the alertable subset, 03-logging-audit.md).
# Any DENIED outcome is a security event too, whatever the action.
SECURITY_ACTIONS: frozenset[AuditAction] = frozenset(
    {
        AuditAction.AUTH_LOGIN_FAILURE,
        AuditAction.AUTH_LOCKOUT,
        AuditAction.AUTH_SESSION_REVOKED,
        AuditAction.AUTH_ACCESS_DENIED,
        AuditAction.USER_ROLE_CHANGED,
        AuditAction.USER_DISABLED,
        AuditAction.TOOL_RUN_DENIED_SCOPE,
        AuditAction.SCOPE_POLICY_CHANGED,
        AuditAction.AUDIT_INTEGRITY_FAILED,
    }
)


def is_security_event(action: AuditAction, outcome: Outcome) -> bool:
    return action in SECURITY_ACTIONS or outcome is Outcome.DENIED
