# Sentinel — Threat model

STRIDE-style and updated every phase. **Last updated:** Phase 8 (2026-10-04), after the
final capstone-core pass in Phase 14. Phases 9–11 (log analysis, FIM,
network diagnostics) will add their own rows (T16 is already reserved for them).

## 1. System overview

```
                  127.0.0.1 only
 Browser ──────► frontend ───────────────► api (FastAPI) ──► postgres ◄── migrate (one-shot,
                 Vite dev server (dev)        │  ▲            (app role:          schema owner)
                 nginx + static build (prod)  ▼  │ pub/sub     DML only)
                                            redis ◄── worker (Celery) ──► lab targets (lab network)
                                                                   └────► internet (egress network:
                                                                          DNS, NVD, in-scope targets)
```

Networks:
- `edge`: frontend and api. In production nginx has a pinned address and is the
  only published port.
- `internal`: api, worker, postgres, redis, migrate. `internal: true`, so no egress.
- `egress`: worker only, for outbound tool traffic.
- `lab`: worker and the lab targets. `internal: true`.

Host ports bind to `127.0.0.1` only. The production profile is described in ADR 0011.

## 2. Assets

| Asset | Why it matters |
|---|---|
| User credentials and sessions | Account takeover gives an attacker the ability to scan as that user |
| Audit trail | Accountability. Tampering would hide misuse |
| Scope policy (Phase 6) | Controls which third parties Sentinel can send traffic to |
| Provider API keys (Phase 8) | Financial and reputational cost if leaked; quota abuse (T70, T73) |
| DB/Redis credentials | Full data access |
| Scan results and findings | Reveal weaknesses in the scanned systems |

## 3. Trust boundaries

1. Browser ↔ API: untrusted input. Everything is validated with Pydantic.
2. API ↔ worker (via Redis): the messages are trusted, but Celery accepts JSON only.
3. Worker ↔ external targets and APIs: responses are hostile data (banners, headers, intel payloads).
4. Containers ↔ host: there are bind mounts in dev, and the host is not exposed to the LAN.
5. nginx ↔ API (production): the API trusts `X-Forwarded-For` from nginx's pinned address only.
6. Exported reports ↔ their readers: report content (banners, headers) is hostile data
   rendered into PDF and CSV (T58, T59).

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
| T10 | E | **Pivoting: active tools aimed at Sentinel's own infra** (postgres, redis, api, metadata IPs) | Hard denylist of pinned infra subnets plus metadata/link-local/multicast ranges, checked after resolution on every address (IPv4-mapped IPv6 unwrapped), never stored in the DB and not overridable by policy; lab targets on a separate internal `lab` network (ADR 0007) | Done (P6) |
| T11 | E | SSRF via header checker or redirects; DNS rebinding | URL shape rules (http/https, allowlisted ports, no credentials/control chars); scope + hard denylist on every hop; IP pinning with Host/SNI; manual redirects re-validated and re-scoped (denials audited); `trust_env=False`; capped bodies/headers (ADR 0008) | Done (P7) |
| T12 | S | Cross-Site WebSocket Hijacking | Origin allowlist on the handshake plus a single-use, 30-second, run-bound ticket from a CSRF-checked POST, redeemed with GETDEL (ADR 0006) | Done (P5) |
| T13 | R | Users deny running scans | Hash-chained, append-only audit log with user, session, IP and request ID on every event (ADR 0003) | Done (P2) |
| T14 | D | Resource exhaustion (huge scans, uploads, slow targets) | Timeouts and caps everywhere; Celery soft/hard limits and prefetch 1; per-user run, playbook and report quotas (T43, T62). Load-tested in P14: 8 users × 30 concurrent runs, all completed, quotas refused 126 requests and the clients retried them, no 5xx | Done (P14); uploads arrive with P10/P11 |
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
| T44 | E | Active tool sending traffic before any authorisation exists | Phase 5 refused all active tools; Phase 6 requires the audited authorised-use acknowledgement plus an in-scope target, checked by API and worker | Done (P6) |
| T45 | E | Worker egress used to reach internal services | Worker is the only service on `egress`; active tools hit the infra hard denylist (T10) before connecting | Done (P6) |
| T46 | T | DNS rebinding between scope check and connection | The worker hands the checked addresses to the tool (`authorized_addresses`); the scanner connects only to them and never re-resolves; it refuses to run without them | Done (P6) |
| T47 | E | Scope bypass via over-broad or ambiguous rules (0.0.0.0/0, a domain resolving partly outside scope, look-alike domains) | Prefixes broader than /8 (IPv4) or /32 (IPv6) refused; overlaps with the denylist refused; every resolved address must be in scope; label-aware suffix matching | Done (P6) |
| T48 | R | Users denying they knew scanning needed permission | Versioned statement acceptance stored (hash, IP, time) in an INSERT/SELECT-only table and audited; required before any active run | Done (P6) |
| T49 | D/I | NVD integration abused or failing (rate-limit bans, slow API, hostile responses) | Shared Redis rate window under NVD limits, bounded retries honouring Retry-After, timeouts, JSON-only cache, capped results/descriptions; failure degrades to a partial result | Done (P6) |
| T50 | T | Misleading CVE matches from spoofed or distro-patched banners | Confidence never HIGH; LOW for distribution builds with backport explanation; every CVE finding states the banner caveat | Done (P6) |
| T51 | E | Lab targets used as a foothold | Lab network is internal (no egress) and joined only by the worker; lab-banners runs no real service, non-root, read-only, all capabilities dropped | Done (P6) |
| T52 | I | Session cookies of scanned sites captured in Sentinel's database | Set-Cookie parsed to name + attributes on receipt; values dropped and raw headers removed; tested | Done (P7) |
| T53 | E | Allowed domain name pointed (by its DNS owner) at internal addresses | Domain rules vouch for public addresses only; non-global addresses also need a CIDR rule (`internal_via_domain`) | Done (P7) |
| T54 | T | Certificate validation weakened by IP pinning | SNI and hostname verification use the original name (prototyped with httpcore `sni_hostname`); unverified handshakes only read certificates or headers of already-failing sites | Done (P7) |
| T55 | E | Code execution or data access through playbook templates | No template engine: strict reference grammar over plain JSON (no attribute access, calls or filters); backward-only references validated at load; size cap | Done (P12) |
| T56 | E | Playbooks used to launder out-of-scope targets through later steps | Every step is created and executed through the same run service and worker scope check as a manual run; the target is pre-checked at start | Done (P12) |
| T57 | D | Orchestrator deadlocking the worker pool by waiting on sub-tasks | Steps execute inline in one orchestrator task; Celery limits summed from the steps; shared per-user caps | Done (P12) |
| T58 | T/E | CSV/formula injection: a banner, header or user agent such as `=HYPERLINK(...)` executing in an analyst's spreadsheet | Cells whose first (or first non-blank) character is `= + - @`, tab, CR, LF or a full-width look-alike get a leading `'`; every cell quoted; cells capped below Excel's limit. Applies to report CSVs and the audit-trail export; tested on real tool output and real audit rows | Done (P13) |
| T59 | T/E | PDF report turning tool output into links, images or font tricks (ReportLab Paragraph markup) | All dynamic text escaped with `xml.sax.saxutils.escape` before reaching a Paragraph; raw data in `Preformatted` (no markup parsing); references printed, never linked; tests assert no `/Annot`, `/URI`, `/JavaScript` or `/Launch` in the output | Done (P13) |
| T60 | I/R | Reports leaking findings without a trace | `report.exported`, `report.generated` and `report.downloaded` audited with the actor, format and SHA-256; download fails closed if the audit write fails; analyst+ to request, viewer+ to read (same as runs); `Cache-Control: no-store` | Done (P13) |
| T61 | T | Stored report altered in the database, then served as genuine | SHA-256 recorded at generation and re-checked on every download; a mismatch is refused (500 `integrity_failed`) and audited as a security event; the app role cannot UPDATE or DELETE `report_blobs` | Done (P13) |
| T62 | D | Report generation exhausting workers or storage | 10 report requests/min and 3 in flight per user; render in a thread under a 60 s timeout plus Celery soft/hard limits; output capped at 20 MB; PDF appendix and evidence truncated | Done (P13) |
| T63 | T | Header injection or path tricks through the download filename | Filename built server-side from an ASCII slug (`[A-Za-z0-9._-]`); the frontend accepts a header filename only if it matches the same pattern | Done (P13) |
| T64 | E/I | Production deployed with dev settings: source mounts, `--reload`, `/docs`, API port exposed, writable filesystems | Separate production override (`docker-compose.prod.yml`): runtime image, no mounts or reload, read-only root filesystems, `ENVIRONMENT=production` (no docs, HSTS, insecure cookies refused), only nginx published. All checked in the CI production smoke job | Done (P14) |
| T65 | S/R | Forged client IPs via `X-Forwarded-For` in audit records and per-IP limits | The API trusts XFF only from nginx's pinned address (not the edge subnet, which contains Docker's gateway); verified that audit records show the real peer | Done (P14) |
| T66 | T | Weak or duplicated security headers on the production front end | nginx sends a strict CSP and the companion headers on the app; API responses keep the API's own stricter headers (no duplicates). CI runs Sentinel's own header checker against the live front end, and any finding above INFO fails the job | Done (P14) |
| T67 | E | A route shipped without an authorization decision | `test_authz_matrix.py` lists every route with its minimum role; a new unclassified route fails the build. Every protected route is checked for 401 (anonymous) and 403 (each lower role, audited) | Done (P14) |
| T68 | D/R | Audit trail flooded with anonymous noise, hiding real events | Cookie-less refresh probes (every anonymous page load) are no longer audited, matching the rule for unauthenticated 401s; malformed refresh cookies still are; per-IP refresh limit unchanged | Done (P14) |
| T69 | I | Weak or reused secrets in fresh installs | `scripts/init-env.sh` / `init-env.ps1` generate every secret from the OS CSPRNG, refuse to overwrite an existing `.env`, and create it owner-readable | Done (P14) |
| T70 | I | Provider API keys leaking through logs, errors, stored results or the API | Keys are `SecretStr` settings passed only in headers (Shodan: query string). Provider errors carry fixed messages, never `str(exc)` (httpx text can include the URL); httpx's logger is held at WARNING; the full provider response is never stored; the catalogue reports `configured: true/false` only. Tests assert keys appear in no stored run data, error or catalogue output | Done (P8) |
| T71 | I | Internal network details disclosed to third parties through lookups | Private, loopback, link-local, documentation and other non-global addresses are never sent (INFO finding instead); internal domain suffixes are rejected; the tool description states that indicators leave Sentinel. Tests prove a private address in the input produces no outbound request | Done (P8) |
| T72 | T | Hostile or poisoned provider data (huge bodies, markup, misleading verdicts) | 1 MB response cap; whitelisted, length-capped fields only; text rendered escaped (React, PDF escaping, CSV formula guard); every finding names its source and links to it; confidence reflects how much evidence backs a verdict; "no reports" is never presented as proof of safety | Done (P8) |
| T73 | D | Provider quota exhaustion or bans (many users, playbook re-runs) | Per-provider budgets in a Redis window shared by all workers (VirusTotal 4/min by default); 429/503 retried with Retry-After or jittered backoff, then a partial result; 6-hour result cache; at most 20 indicators per run; run quotas still apply | Done (P8) |
| T74 | E/D | A misconfigured tool queued and failing repeatedly | Generic `availability()` hook: the API refuses runs of unconfigured tools with 409 and a reason; playbooks skip optional unconfigured steps | Done (P8) |

## 5. Accepted risks and environment notes

- **Dev CSP is relaxed.** Vite HMR needs inline scripts. The strict CSP only ships in the production nginx image.
- **The dev filesystem is writable.** `read_only` root filesystems are applied in the production profile (Phase 14), because the dev servers write caches.
- **The Redis password is visible in the redis container's process args.** It's acceptable inside an isolated container. The production profile can switch to a mounted config file or Docker secret.
- **Tamper evidence has limits.** The hash chain detects tampering by the app role. It does not stop the table owner (who can disable the triggers) or a DB superuser, and deleting the newest rows leaves a valid shorter chain. Anchoring `head_hash` externally, plus log shipping or WORM storage, is the production answer (ADR 0003).
- **Unauthenticated 401s are not audited.** Auditing them would let anonymous requests flood the audit table. Failed logins and refreshes are audited behind rate limits.
- **Concurrent refreshes from two tabs** look like token reuse and revoke the session. The Phase 3 client single-flights refreshes.
- **Per-IP limits behind a proxy** need `TRUSTED_PROXIES`, otherwise all users share one bucket.
- **The production profile serves plain HTTP on localhost.** TLS termination (and with it,
  meaningful HSTS) is left to the deployment: a reverse proxy or load balancer in front of
  nginx. Safari and WebKit do not send `Secure` cookies to `http://localhost`, so they need
  TLS (or `COOKIE_SECURE=false` in development) to sign in.
- **Reports have no retention limit.** The app role cannot delete reports (they are a
  record of what was disclosed). Purging old reports is an owner-role maintenance task;
  retention rules are left to the deployment's data policy.
- **The observability profile (OpenTelemetry, Prometheus, Loki) is not built.** The spec
  marks it optional. JSON logs with request IDs on every line (shippable by any Docker
  logging driver) are the current answer.
- **PDF reports use the standard Helvetica/Courier fonts.** Characters outside Latin-1 (CJK, Cyrillic, emoji) render as boxes in the PDF; the CSV, JSON and text exports keep them intact. Embedding a Unicode TTF would fix it at the cost of a bundled font file.
- **Docker Desktop on Windows:** traceroute is best-effort, and FIM metadata on bind mounts is unreliable. See PROGRESS.md.
