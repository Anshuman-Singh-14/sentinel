# 03 — Enterprise Logging, Identity & Audit

Sentinel needs to answer, for any action: **who did what, to which target, when, from where, with what result** — without ever leaking secrets or sensitive user input. This is split into three streams with different purposes.

| Stream | Purpose | Storage | Retention (configurable) |
|---|---|---|---|
| Application logs | Debugging, operations | JSON to stdout (Docker collects) + optional rotating file | 14–30 days |
| Audit log | Accountability, security investigations | PostgreSQL `audit_events`, append-only, hash-chained | 1 year+ |
| Security events | Alertable subset (auth failures, scope violations, tamper detection) | Audit log with `is_security_event=true` + WARNING/ERROR app logs | as audit |

Scope note: Sentinel logs what users do **inside Sentinel** (authenticated actions, tool runs, admin changes) and the system identity of the process performing work. It does not monitor users' activity on their own machines, and it never records the inputs of the client-side tools.

---

## 1. User identity (prerequisite for attribution)

- Local user accounts with Argon2id password hashing (`argon2-cffi`), minimum password policy, account lockout after N failures with backoff
- First admin created via a CLI command (`python -m app.cli create-admin`), never via a default password
- Auth: short-lived access token + rotating refresh token stored in an httpOnly, Secure, SameSite=Strict cookie. CSRF protection for cookie-authenticated state-changing requests
- RBAC roles: `admin` (users, scope policy, provider config, audit viewer), `analyst` (run tools/playbooks, export), `viewer` (read results)
- WebSocket auth: validate the session on connect (cookie or a one-time ticket from a REST endpoint); never put tokens in the query string, since URLs end up in logs
- Sessions table records created_at, last_seen, IP, user agent; admins can revoke sessions

## 2. Actor context captured on every event

**User context** (from the authenticated request): `user_id`, `username`, `role`, `session_id`, `source_ip` (respect `X-Forwarded-For` only from configured trusted proxies), `user_agent`.

**System context** (for worker and system events; gathered with stdlib only, no shell): `service` (`api`/`worker`/`beat`), `hostname` (`socket.gethostname()`), `process_user` (`getpass.getuser()` / `os.getuid()`), `pid`, `app_version`, `environment`.

**Correlation:** `request_id` (from `X-Request-ID` or generated UUIDv7, echoed in the response header), `run_id`, `playbook_run_id`, `celery_task_id`. Stored in `contextvars` in the API and propagated to Celery via task headers so a single ID ties an HTTP request, its worker execution, its logs and its audit events together.

## 3. Application logging (structlog)

- JSON renderer in all non-dev environments; pretty console renderer in dev
- Standard fields: `timestamp` (UTC ISO-8601), `level`, `event`, `logger`, `service`, `request_id`, `user_id`, `run_id`, plus event-specific fields
- Stdlib `logging` (uvicorn, celery, sqlalchemy) routed through structlog so everything is one format
- Middleware logs one access line per request: method, route template (not raw path with IDs), status, duration_ms, user_id, request_id
- Levels: DEBUG off in production; INFO for lifecycle; WARNING for recoverable problems (provider 429, partial results); ERROR with exception info for failures
- Configurable via env: `LOG_LEVEL`, `LOG_FORMAT`, `LOG_FILE_PATH`, `LOG_RETENTION_DAYS`

## 4. Redaction (mandatory processor)

A structlog processor, applied to every log and every audit `details` payload before it is written:

- Key-based: mask values for keys matching `password|passwd|secret|token|api[_-]?key|authorization|cookie|session|private[_-]?key|refresh` (case-insensitive, nested dicts/lists)
- Pattern-based: JWTs (`eyJ...\.eyJ...\..*`), `Bearer ...`, common API key formats, AWS-style keys, long high-entropy strings in suspicious fields
- Output shows `"[REDACTED]"` (optionally with a short hash fingerprint for correlation, never the value)
- Truncate oversized fields (raw banners, response bodies) with a length marker
- Security tests in `tests/security/test_redaction.py` prove secrets injected into every log path never appear in output

## 5. Audit log

**Table `audit_events`:**
`id` (bigint, sequential), `event_id` (uuid), `occurred_at`, `actor_type` (`user`/`system`/`anonymous`), `user_id`, `username`, `role`, `session_id`, `source_ip`, `user_agent`, `service`, `hostname`, `process_user`, `action`, `resource_type`, `resource_id`, `target`, `outcome` (`SUCCESS`/`FAILURE`/`DENIED`), `reason`, `details` (JSONB, redacted), `request_id`, `is_security_event`, `prev_hash`, `row_hash`.

**Action taxonomy** (dotted, stable strings, defined as an Enum):
- `auth.login.success`, `auth.login.failure`, `auth.lockout`, `auth.logout`, `auth.token.refresh`, `auth.session.revoked`
- `user.created`, `user.role.changed`, `user.disabled`, `user.password.changed`
- `tool.run.requested`, `tool.run.denied_scope`, `tool.run.started`, `tool.run.completed`, `tool.run.failed`, `tool.run.cancelled`
- `playbook.run.requested` … (same lifecycle)
- `scope.policy.changed`, `scope.authorization.acknowledged`
- `provider.config.changed` (which provider, enabled/disabled — never the key)
- `fim.baseline.created`, `fim.baseline.deleted`, `fim.check.completed`
- `log.analysis.requested` (file name/size, not contents)
- `report.generated`, `report.exported`, `report.downloaded`
- `audit.exported`, `audit.integrity.verified`, `audit.integrity.failed`

**Tamper evidence:**
- `row_hash = SHA-256(prev_hash || canonical_json(event_without_hashes))`; first row uses a genesis hash
- Inserts serialized (advisory lock) so the chain is linear
- Postgres trigger rejects `UPDATE` and `DELETE` on `audit_events`; the app DB role is granted `INSERT, SELECT` only on that table
- `POST /api/v1/admin/audit/verify` recomputes the chain and reports the first broken link; a scheduled verification can run via beat
- Document the limit honestly: this detects tampering by the app role, not by a DB superuser. Mention external log shipping / WORM storage as the production answer

**Write path:** an `AuditService.record(...)` async function used through a FastAPI dependency and a Celery helper. Audit writes for denied/failed actions must never be skipped because the main action failed. If the audit write itself fails for a security-relevant action, the action fails closed.

## 6. Audit viewer (frontend, admin only)

- Filterable table (user, action, outcome, target, date range, security events only), detail drawer showing full redacted event and linked run
- Integrity verification button with result
- Export filtered results to CSV/JSON (itself audited)

## 7. Security alerting hooks (simple v1)

- Rules evaluated on audit insert: N failed logins for a user/IP in T minutes, scope denial bursts, integrity verification failure
- v1 action: WARNING log + dashboard notification badge. Design an `AlertSink` interface so email/webhook/Slack sinks can be added later

## 8. Optional later (Phase 14)

- OpenTelemetry traces for API → worker spans
- Log shipping to Loki/Grafana or ELK via Docker logging driver (compose profile `observability`)
- Prometheus metrics: request latency, task durations, queue depth, failures by tool
