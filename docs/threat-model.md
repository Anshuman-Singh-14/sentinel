# Sentinel — Threat model

STRIDE-style and updated every phase. **Last updated:** Phase 2 (2026-10-02).

## 1. System overview

```
 Browser ──► frontend (Vite dev / nginx) ──► api (FastAPI) ──► postgres ◄── migrate (one-shot, schema owner)
                                               │  ▲
                                               ▼  │ pub/sub
                                             redis ◄── worker (Celery) ──► [targets, Phase 5+]
```

Networks: `edge` (frontend, api) and `internal` (api, worker, postgres, redis;
`internal: true`, so no egress). Host ports bind to `127.0.0.1` only.

## 2. Assets

| Asset | Why it matters |
|---|---|
| User credentials and sessions | Account takeover gives an attacker the ability to scan as that user |
| Audit trail | Accountability. Tampering would hide misuse |
| Scope policy (Phase 6) | Controls which third parties Sentinel can send traffic to |
| Provider API keys (Phase 8) | Financial and reputational cost if leaked |
| DB/Redis credentials | Full data access |
| Scan results and findings | Reveal weaknesses in the scanned systems |

## 3. Trust boundaries

1. Browser ↔ API: untrusted input. Everything is validated with Pydantic.
2. API ↔ worker (via Redis): the messages are trusted, but Celery accepts JSON only.
3. Worker ↔ external targets and APIs: responses are hostile data (banners, headers, intel payloads).
4. Containers ↔ host: there are bind mounts in dev, and the host is not exposed to the LAN.

## 4. Threats and mitigations

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T1 | E | Code execution via shell or deserialization | No subprocess/eval/pickle (AST test + bandit). Celery is JSON-only | Done (P0) |
| T2 | I | Secrets committed to git | `.env` gitignored, gitleaks in pre-commit and CI, `SecretStr` settings | Done (P0) |
| T3 | I | DB/Redis reachable from the LAN or host | No published ports, internal network, Redis `requirepass` | Done (P0) |
| T4 | E | App compromise leads to DB superuser | App uses `sentinel_app` (DML only, no DDL); the superuser password is only given to the postgres container | Done (P0) |
| T5 | E | Container breakout or privilege use | Non-root UID 10001, `cap_drop: ALL`, `no-new-privileges` | Done (P0) |
| T6 | I | Readiness errors leak DSNs or hosts | `/ready` returns only ok/fail per component and logs only the exception type | Done (P0) |
| T7 | T | Clickjacking, MIME sniffing | API sends CSP `frame-ancestors 'none'`, `nosniff`, `X-Frame-Options: DENY`. Prod nginx has a strict CSP | Done (P0) |
| T8 | S | Cross-origin credentialed requests | Explicit CORS allowlist (`*` rejected at startup). Dev uses a same-origin proxy | Done (P0) |
| T9 | T | Stored XSS from tool output | ESLint bans `dangerouslySetInnerHTML`. All data renders as React text; `JsonViewer` never creates links; tested with `<script>`/`javascript:` payloads (ADR 0004) | Done for the shell (P3); re-checked per result viewer |
| T10 | E | **Pivoting: active tools aimed at Sentinel's own infra** (postgres, redis, api, metadata IPs) | Hard infra denylist the scope policy cannot override, and lab targets on a separate `lab` network | Planned (P6/P7) |
| T11 | E | SSRF via header checker or redirects; DNS rebinding | SSRF guard: scheme/port allowlist, IP pinning, re-validation on every redirect | Planned (P7) |
| T12 | S | Cross-Site WebSocket Hijacking | Origin allowlist on the handshake plus a single-use, 30-second, run-bound ticket from a CSRF-checked POST, redeemed with GETDEL (ADR 0006) | Done (P5) |
| T13 | R | Users deny running scans | Hash-chained, append-only audit log with user, session, IP and request ID on every event (ADR 0003) | Done (P2) |
| T14 | D | Resource exhaustion (huge scans, uploads, slow targets) | Timeouts and caps everywhere. Celery soft/hard limits and prefetch 1. Per-user quotas | Partial (P0 Celery limits) |
| T15 | I | Secrets in logs | Mandatory redaction processor on every record, including stdlib loggers, tracebacks and the uvicorn supervisor (ADR 0002) | Done (P1) |
| T16 | T | Path traversal in log analyzer or FIM | PathGuard and read-only mounts | Planned (P10/P11) |
| T17 | T | Supply-chain compromise | Exact pins and lockfiles, pip-audit, npm audit, Dependabot | Done (P0) |
| T18 | T/R | Log injection or forging via `X-Request-ID` (newlines, ANSI, huge values) | Strict request-ID format, otherwise replaced with a UUIDv7. Re-validated in the worker | Done (P1) |
| T19 | I | Library logs leaking data: raw paths and query strings (uvicorn access), SQL parameters (sqlalchemy), outbound URLs with keys (httpx) | Those loggers capped at WARNING. Our access log records route templates only | Done (P1) |
| T20 | I | Validation errors echoing submitted secrets back in the response | 422 bodies carry only `loc`, `msg`, `type`, never `input` | Done (P1) |
| T21 | I | Stack traces or driver errors reaching clients | Exception hierarchy and handlers. Last-resort 500 built in the outermost middleware with request ID and security headers | Done (P1) |
| T22 | E | App role altering schema or the audit table | Migrations run only in the one-shot `migrate` container as `sentinel_owner`. `sentinel_app` has DML only, verified in CI | Done (P1) |
| T23 | E | Malicious YAML in the knowledge base (object construction) | `yaml.safe_load` only (AST test bans `yaml.load`), Pydantic-validated, 1 MB cap, `string.Template` rendering (no attribute access) | Done (P1) |
| T24 | S | Online password guessing and password spraying | Argon2id; per-account lockout with exponential backoff; per-IP Redis rate limit on login and refresh (fails closed); failed-login burst alert | Done (P2) |
| T25 | I | Username enumeration via responses or timing | One 401 body for every failure; dummy Argon2 verify for unknown, disabled and locked accounts; real reason only in the audit log | Done (P2) |
| T26 | S | Session theft via XSS or a database leak | Tokens in HttpOnly `__Host-`/`__Secure-` cookies; only SHA-256 digests stored; 15-minute access tokens; 24-hour absolute session lifetime | Done (P2) |
| T27 | S | Stolen refresh token replayed | Rotation on every refresh; reuse of a rotated token revokes the session and raises a HIGH alert | Done (P2) |
| T28 | T | CSRF, including login CSRF and cookie injection | SameSite=Strict, Origin allowlist on every write (login included), session-bound double-submit token | Done (P2) |
| T29 | E | Privilege escalation or admin lock-out | Hierarchical RBAC dependencies tested for every role; denials audited; no self role change or self disable; last-admin guard; disabling revokes sessions | Done (P2) |
| T30 | T/R | Audit tampering by the app role | INSERT/SELECT-only grant, UPDATE/DELETE/TRUNCATE triggers, hash chain plus verify endpoint and CRITICAL alert. Owner/superuser tampering remains possible; see section 5 | Done (P2) |
| T31 | D | Memory exhaustion via concurrent Argon2 hashing | Hash concurrency capped at 4 (about 256 MiB); login input capped at 1024 characters, policy at 128; per-IP rate limit | Done (P2) |
| T32 | I | Secrets or passwords in audit details | Details pass through the redaction processor before hashing; attempted passwords are never recorded; the login username field is length-capped | Done (P2) |
| T33 | S/I | Open redirect via `/login?next=` used for phishing | `safeRedirectPath` accepts same-origin paths only; protocol-relative, backslash, control-char and overlong values fall back to `/` | Done (P3) |
| T34 | I | Session cookies sent to another origin by a client bug | API client refuses non-path URLs, `credentials: "same-origin"`, `redirect: "error"` | Done (P3) |
| T35 | D | Concurrent refreshes from several tabs tripping refresh-reuse detection (self-inflicted session revocation) | Single-flight refresh per tab plus a Web Locks mutex across tabs | Done (P3) |
| T36 | D | Hostile, huge or deeply nested tool output freezing the browser | `JsonViewer` caps depth, items and string length; the full value stays available through Copy | Done (P3) |
| T37 | I | Data cached under one identity shown to the next user on a shared browser | Query cache cleared on login, logout and session expiry; rejected passwords cleared from state | Done (P3) |
| T38 | I | Client-side tool input (passwords, tokens, secrets, files) leaking to the server, logs or storage | Tools live in their own modules; a static import-graph test bans the API client, network, storage and console APIs; a runtime test drives every tool with all network APIs trapped; input fields disable autocomplete and spellcheck (ADR 0005) | Done (P4) |
| T39 | T | JWT inspector misleading users: "decoded" read as "verified", or algorithm confusion | Prominent "decoding is not verifying" banner; verification pins the key type to the header's algorithm and refuses public keys as HMAC secrets, `alg: none`, and private keys | Done (P4) |
| T40 | D | Hostile input freezing the browser (huge paste, pathological password, multi-GB file) | Input caps (1 M chars encoder, 64 KB token, 256 chars to zxcvbn), deferred rendering, chunked file hashing with a 4 GiB cap and cancel | Done (P4) |
| T41 | I | DNS tool used to enumerate internal infrastructure (resolving `postgres`, `redis`, `*.internal`) | Explicit public upstream resolvers instead of Docker's embedded DNS; single-label, IP-literal and private/reserved-suffix names rejected at validation; PTR only for public IPs | Done (P5) |
| T42 | T | Tampered or replayed task messages altering what a worker runs | Task carries only the run id; parameters are read from the database and re-validated; compare-and-set claim means a run executes at most once; a redelivered RUNNING run is failed, not re-run | Done (P5) |
| T43 | D | One account flooding the workers | 20 runs/min per user, max 3 active runs per user, per-tool time limits in three layers, raw output capped at 1 MB | Done (P5) |
| T44 | E | Active tool sending traffic before any authorisation exists | Fail-closed: every `is_active` tool is refused and audited as a security event until the Phase 6 scope policy | Done (P5, replaced in P6) |
| T45 | E | Worker egress used to reach internal services | The worker is the only service on the `egress` network; active tools additionally get the infra denylist in Phase 6 (T10) | Partial (P5) |

## 5. Accepted risks and environment notes

- **Dev CSP is relaxed.** Vite HMR needs inline scripts. The strict CSP only ships in the production nginx image.
- **The dev filesystem is writable.** `read_only` root filesystems are applied in the production profile (Phase 14), because the dev servers write caches.
- **The Redis password is visible in the redis container's process args.** It's acceptable inside an isolated container. The production profile can switch to a mounted config file or Docker secret.
- **Tamper evidence has limits.** The hash chain detects tampering by the app role. It does not stop the table owner (who can disable the triggers) or a DB superuser, and deleting the newest rows leaves a valid shorter chain. Anchoring `head_hash` externally, plus log shipping or WORM storage, is the production answer (ADR 0003).
- **Unauthenticated 401s are not audited.** Auditing them would let anonymous requests flood the audit table. Failed logins and refreshes are audited behind rate limits.
- **Concurrent refreshes from two tabs** look like token reuse and revoke the session. The Phase 3 client single-flights refreshes.
- **Per-IP limits behind a proxy** need `TRUSTED_PROXIES`, otherwise all users share one bucket.
- **Docker Desktop on Windows:** traceroute is best-effort, and FIM metadata on bind mounts is unreliable. See PROGRESS.md.
