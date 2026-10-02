/**
 * Audit action taxonomy, mirroring backend/app/core/audit/actions.py.
 * Used only to populate the filter dropdown; the backend validates the value.
 */
export const AUDIT_ACTIONS = [
  "auth.login.success",
  "auth.login.failure",
  "auth.lockout",
  "auth.logout",
  "auth.token.refresh",
  "auth.session.revoked",
  "auth.access.denied",
  "user.created",
  "user.role.changed",
  "user.disabled",
  "user.enabled",
  "user.password.changed",
  "tool.run.requested",
  "tool.run.denied_scope",
  "tool.run.started",
  "tool.run.completed",
  "tool.run.failed",
  "tool.run.cancelled",
  "playbook.run.requested",
  "playbook.run.started",
  "playbook.run.completed",
  "playbook.run.failed",
  "playbook.run.cancelled",
  "scope.policy.changed",
  "scope.authorization.acknowledged",
  "provider.config.changed",
  "fim.baseline.created",
  "fim.baseline.deleted",
  "fim.check.completed",
  "log.analysis.requested",
  "report.generated",
  "report.exported",
  "report.downloaded",
  "audit.exported",
  "audit.integrity.verified",
  "audit.integrity.failed",
] as const;

export const AUDIT_OUTCOMES = ["SUCCESS", "FAILURE", "DENIED"] as const;
