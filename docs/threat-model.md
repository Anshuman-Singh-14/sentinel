# Sentinel — Threat model

STRIDE-style and updated every phase. **Last updated:** Phase 1 (2026-10-01).

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
| User credentials and sessions (Phase 2) | Account takeover gives an attacker the ability to scan as that user |
| Audit trail (Phase 2) | Accountability. Tampering would hide misuse |
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
| T9 | T | Stored XSS from tool output | ESLint bans `dangerouslySetInnerHTML`. Output is rendered as text | Partial (P0 lint, P3+ UI) |
| T10 | E | **Pivoting: active tools aimed at Sentinel's own infra** (postgres, redis, api, metadata IPs) | Hard infra denylist the scope policy cannot override, and lab targets on a separate `lab` network | Planned (P6/P7) |
| T11 | E | SSRF via header checker or redirects; DNS rebinding | SSRF guard: scheme/port allowlist, IP pinning, re-validation on every redirect | Planned (P7) |
| T12 | S | Cross-Site WebSocket Hijacking | Origin check on connect plus a single-use short-lived WS ticket | Planned (P5) |
| T13 | R | Users deny running scans | Hash-chained, append-only audit log with attribution | Planned (P2) |
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

## 5. Accepted risks and environment notes

- **Dev CSP is relaxed.** Vite HMR needs inline scripts. The strict CSP only ships in the production nginx image.
- **The dev filesystem is writable.** `read_only` root filesystems are applied in the production profile (Phase 14), because the dev servers write caches.
- **The Redis password is visible in the redis container's process args.** It's acceptable inside an isolated container. The production profile can switch to a mounted config file or Docker secret.
- **Tamper evidence has limits** (Phase 2). The hash chain detects tampering by the app role, not by a DB superuser. External log shipping or WORM storage is the production answer.
- **Docker Desktop on Windows:** traceroute is best-effort, and FIM metadata on bind mounts is unreliable. See PROGRESS.md.
