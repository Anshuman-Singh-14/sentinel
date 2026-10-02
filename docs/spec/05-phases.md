# 05 — Build Phases

Work strictly in order. For each phase: plan → my approval → implement → test → phase report → stop.

> **Approved order change (2026-10-02, ADR 0009):** after Phase 7 the remaining phases are
> built **12 → 13 → 14 → 8 → 10 → 11 → 9**, so the core demo (playbook → report → polish)
> is finished before the stretch phases. ADR 0009 lists the dependency checks and what each
> deferred phase must update when it lands.
"Done" means every acceptance criterion is met, tests pass, lint/type/bandit are clean, and `docs/PROGRESS.md` is updated.

---

### Phase 0 — Foundation & tooling
Scaffold repo per `01-architecture.md`; Dockerfiles; `docker-compose.yml` (frontend, api, worker, redis, postgres); `.env.example`; pre-commit (ruff, mypy, bandit, eslint, prettier, gitleaks); GitHub Actions CI; `/health` and `/ready` endpoints; `docs/PROGRESS.md`, `docs/threat-model.md` skeleton, first ADR.
**Accept:** `docker compose up` brings all services healthy; CI green; frontend shows a placeholder page calling `/health`.

### Phase 1 — Core backend framework & logging foundation
`config.py`; structlog setup, request-ID middleware, contextvar propagation, redaction processor; async DB session; Alembic baseline; error hierarchy and handlers; `engine/schemas.py` (ToolResult, Finding, Severity), `BaseTool`, registry, severity helpers, knowledge YAML loader; a trivial `echo` tool to prove the contract.
**Accept:** JSON logs with request_id on every line; redaction tests pass; registry lists the echo tool; migration runs cleanly.

### Phase 2 — Identity, RBAC & audit trail
Users/roles/sessions models; Argon2id; login/logout/refresh; lockout; RBAC dependencies; create-admin CLI; `audit_events` with hash chain, DB trigger and restricted grants; `AuditService`; verify endpoint; alert rule for failed logins.
**Accept:** every auth action produces an audit event; UPDATE/DELETE on audit table is rejected; verify endpoint detects a manually broken chain in a test; authz tests pass.

### Phase 3 — Frontend shell & design system
Layout (sidebar, top bar, status area), routing, auth pages, protected routes, API client with CSRF, TanStack Query, UI primitives (Card, Badge, SeverityBadge, DataTable, JsonViewer, Tabs, Toast), tool registry-driven navigation, cyberpunk/industrial theme with accessible contrast.
**Accept:** login works end to end; navigation built from registry; components have vitest coverage.

### Phase 4 — Client-side utilities
Password analyzer, JWT inspector, hash tool, encoder/decoder per `02-modules.md`, each with the local-only badge and explainer panels.
**Accept:** unit tests for each algorithm; a test asserting no API/network calls from these features; works offline.

### Phase 5 — Task infrastructure & first backend tool (DNS)
Celery app and queues; base task wrapping BaseTool (persistence, audit, timing, errors, cancel, time limits); progress publisher; Redis pub/sub → WebSocket relay with auth; generic run endpoints; frontend `useRunStatus` hook and result viewer (findings tab + raw tab); DNS tool complete.
**Accept:** DNS run goes QUEUED→RUNNING→COMPLETED live in the UI; cancel works; failure renders structured error; run history page lists runs.

### Phase 6 — Scope policy & Port Scanner
ScopePolicy model, admin UI, authorization acknowledgement; port scanner with presets, concurrency, banners; NVD enrichment with cache.
**Accept:** out-of-scope targets denied and audited; scan of a local test container (compose `lab` profile with a few services) finds expected ports; CVE matches show confidence and rationale.

### Phase 7 — HTTP Security Header & TLS Checker
SSRF guard; header, cookie and TLS checks; remediation snippets.
**Accept:** SSRF security tests pass; checks produce correct findings against fixture servers (good/bad header configs, expired/self-signed certs).

### Phase 8 — Threat Intelligence Integrator
Provider interface, three providers, concurrency, caching, rate limiting, partial results, source attribution.
**Accept:** providers mocked in tests (respx); missing keys disable providers gracefully; 429 handling tested.

### Phase 9 — Network Diagnostics
Ping and traceroute via icmplib; environment capability detection; TCP ping fallback.
**Accept:** works in compose with documented capability settings; returns "unsupported" cleanly without them.

### Phase 10 — Log File Analyzer
Upload + LOG_ROOT modes; parser plugins; YAML detection rules; streaming processing.
**Accept:** sample auth.log and nginx logs in `tests/fixtures` yield expected detections; traversal tests pass; large file processed within memory bounds.

### Phase 11 — File Integrity Monitor
FIM roots, baseline create/compare, severity by path sensitivity, optional beat schedule.
**Accept:** tests detect modified/added/removed/permission-changed files; symlink escape blocked.

### Phase 12 — Playbook Engine
Definition schema, safe step-output references, orchestrator task, aggregation, UI with step timeline; Web Defensive Audit playbook.
**Accept:** full playbook runs against lab target with live step progress; step failure honours `on_failure`; cancel propagates.

### Phase 13 — Reporting & Export
Exporter plugins (PDF, JSON, CSV, TXT), report task, report history, download endpoints, audit events.
**Accept:** professional PDF for a playbook run; CSV injection test passes; exports audited.

### Phase 14 — Observability, hardening & capstone polish
Optional OpenTelemetry/Prometheus/Loki profile; production compose profile (nginx, no dev servers); full security test pass; load test of concurrent runs; README with architecture diagram, setup, screenshots, security design and ethics statement; final threat model.
**Accept:** fresh clone → `docker compose up` → working demo in under 10 minutes following README.
