# ADR 0003 — Identity, sessions and the tamper-evident audit trail

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 2

## Context

From Phase 2 every action has to be attributable to an authenticated user
(CLAUDE.md rule 5), and the record of those actions has to resist tampering
(03-logging-audit.md section 5). Sentinel runs as a browser SPA behind a
same-origin proxy (the Vite dev server now, nginx in production) talking to
FastAPI. Security matters more here than convenience: a stolen session lets an
attacker run scans under someone else's name.

## Decisions

### 1. Opaque, hashed session tokens instead of JWTs

Each login creates a `sessions` row holding the **SHA-256 digests** of three
256-bit random tokens: access (15 min), refresh (12 h idle, 24 h absolute) and
CSRF. Every authenticated request looks up the access-token digest with one
indexed query.

- **Instant revocation.** Admin revocation, logout, disabling a user and
  password change all take effect on the next request. With JWTs, a revoked
  token stays valid until it expires unless every request checks a denylist,
  and then the token is no longer self-contained anyway.
- **No JWT-specific bug classes.** `alg: none`, algorithm confusion, key
  management and claim validation all go away. The tokens are random values
  with no structure to attack.
- **A database leak is not a session leak.** Only digests are stored. A fast
  hash is safe here because the tokens have 256 bits of entropy, unlike
  passwords.
- **Cost:** one indexed lookup per request, plus a `last_seen_at` write at most
  once a minute. That is negligible at Sentinel's scale.

### 2. Refresh rotation with reuse detection

Every refresh replaces all three tokens and keeps the previous refresh digest.
If that previous token is ever presented again, two parties hold copies, so
the whole session is revoked. This is recorded as a security event
(`auth.session.revoked`, reason `refresh_token_reuse`) and raises a HIGH
alert.

**Trade-off:** two browser tabs refreshing at the same moment look like reuse.
The Phase 3 API client must serialise refreshes (single-flight).

### 3. Cookies

| Cookie | Flags | Path |
|---|---|---|
| `__Host-sentinel_access` | HttpOnly, Secure, SameSite=Strict | `/` |
| `__Secure-sentinel_refresh` | HttpOnly, Secure, SameSite=Strict | `/api/v1/auth` |
| `__Host-sentinel_csrf` | Secure, SameSite=Strict (readable by JS) | `/` |

- **HttpOnly** keeps the bearer tokens away from JavaScript, so an XSS bug
  cannot steal them.
- **The `__Host-` prefix** makes the browser refuse cookies that a sibling
  subdomain tries to plant or overwrite.
- **The refresh cookie only travels to the auth endpoints.**
- **`COOKIE_SECURE=false`** is a dev-only escape hatch for Safari, which does
  not treat `http://localhost` as secure. Production refuses to start with it.

### 4. CSRF: three layers

1. `SameSite=Strict` on every cookie.
2. An `Origin` allowlist check (`CORS_ORIGINS`) on every state-changing request,
   including login and refresh. This blocks login CSRF.
3. A **session-bound** double-submit token. The `X-CSRF-Token` header must
   equal the CSRF cookie *and* hash to the digest stored on the session row. A
   plain double-submit is beaten by cookie injection; binding the token to the
   session closes that gap.

### 5. Passwords and brute force

- **Hashing:** Argon2id with argon2-cffi's defaults (RFC 9106 low-memory
  profile: t=3, m=64 MiB, p=4). Stored hashes are upgraded on login when the
  parameters change.
- **Event loop and memory:** hashing runs in a worker thread so it never
  blocks the event loop. A semaphore caps concurrent hashes at 4, bounding
  memory to about 256 MiB.
- **Policy:** NIST SP 800-63B style. 12 to 128 characters, at least 5
  distinct characters, must not contain the username, and must not be on a
  bundled blocklist. There are no composition rules.
- **Per-account lockout:** after 5 consecutive failures the account locks for
  60 s, doubling with each further failure up to 15 min. A success resets the
  counter.
- **Per-IP rate limit:** 10 login or refresh attempts per minute. Lockout
  alone cannot stop password spraying (one guess against many accounts).
- **No user enumeration:** every login failure returns the same 401 body.
  Unknown, disabled and locked accounts are still checked against a dummy
  Argon2 hash, so they take as long as real ones. The real reason is recorded
  only in the audit log.

**Deviation from the spec (slowapi).** The rate limiter is a ~60-line Redis
fixed-window counter (`INCR` plus `EXPIRE NX` in one MULTI/EXEC), called
explicitly where a limit applies. slowapi is decorator-based, needs a
`request` argument on every endpoint and is thinly maintained. When Redis is
unreachable the limiter fails **closed** (503): dropping brute-force
protection silently would be worse than a short outage.

### 6. RBAC

Roles are strictly hierarchical: admin ≥ analyst ≥ viewer. Each check is one
comparison (`require_viewer`, `require_analyst`, `require_admin`) and is
tested exhaustively. A denial is audited as `auth.access.denied`. That action
is **added to the spec's taxonomy** so that authorization probing leaves a
trail. **Deviation:** there is no `roles` table. The role set is fixed, so a
check-constrained column on `users` is simpler and just as safe.

Guard rails: an admin cannot change their own role or disable their own
account, and the last active admin cannot be demoted or disabled. Disabling a
user, or changing a password, revokes the user's other sessions immediately.

### 7. Audit trail

- **Append-only, in three layers:**
  - `sentinel_app` is granted `INSERT, SELECT` only on `audit_events`.
  - Triggers reject `UPDATE`, `DELETE` (row-level) and `TRUNCATE`
    (statement-level) for every role, including the owner.
  - `id` is `GENERATED ALWAYS`.
- **Hash chain:** `row_hash = SHA-256(prev_hash ‖ "|" ‖ canonical_json(row))`,
  starting from a genesis hash of 64 zeros.
  - **Canonical JSON:** sorted keys, no whitespace, UTF-8, UTC timestamps with
    microseconds, UUIDs as strings.
  - **What is hashed:** every column except `id` and the two hashes.
  - **Exact round trip:** `details` is redacted and passed through JSON before
    hashing, so what is hashed is exactly what JSONB stores.
- **Linear chain:** every insert takes `pg_advisory_xact_lock` before reading
  the previous hash, so concurrent writers cannot fork the chain. A test with
  25 parallel writers proves it.
- **Write path:**
  - `record(session=...)` joins the caller's transaction, so a change and its
    audit row commit together.
  - `record()` without a session commits on its own transaction. It is used for
    failures and denials, so they are recorded even when the main transaction
    rolls back.
  - A failed audit write raises `AuditUnavailable` (503): the action **fails
    closed**.
- **Verification:** `POST /api/v1/admin/audit/verify` streams the chain in
  batches of 1000 by `id` and returns `ok`, `checked`, `head_hash` and the first
  broken id with a reason. It records `audit.integrity.verified` or
  `audit.integrity.failed`; a failure raises a CRITICAL alert.
- **Alerts (v1):**
  - Rules: N failed logins for one user or one IP within T minutes, refresh
    token reuse, and integrity failure.
  - Sinks: a WARNING log line and a `security_alerts` row for the Phase 3
    badge.
  - New sinks implement `AlertSink.emit`.

## Limits, stated honestly

- **The owner and superusers can rewrite history.** The table owner can
  disable the triggers, and a superuser can do anything. The integration tests
  rely on exactly this to tamper on purpose. The chain then detects edits and
  deletions *unless* the attacker rewrites every later row. The production
  answer is to ship events off the database host (log shipping, WORM/object
  lock storage) or to periodically anchor `head_hash` somewhere the database
  cannot reach.
- **Truncating the tail is invisible to the chain alone.** Removing the newest
  rows leaves a valid shorter chain. Recording `head_hash` and `checked`
  externally detects it.
- **Unauthenticated 401s are not audited.** Every anonymous request would
  otherwise become an audit row, which an attacker could use to flood the
  table. Failed logins and refreshes *are* audited, with rate limits in front.
- **Fixed-window rate limits** allow up to twice the limit across a window
  boundary. That is acceptable for brute-force throttling.

## Consequences

- **Integration tests need a real database.** They run in a compose `test`
  profile against a separate `sentinel_test` database and Redis DB 15, so
  tamper tests can never touch dev data. CI runs them in the compose job.
- **The frontend (Phase 3) must:**
  - send `credentials: "include"`;
  - read the `__Host-sentinel_csrf` cookie and send it back as
    `X-CSRF-Token`;
  - single-flight `/auth/refresh` on 401.
- **Behind a reverse proxy, `TRUSTED_PROXIES` must be set.** Otherwise every
  user shares the proxy's IP, and with it the per-IP login limit.
