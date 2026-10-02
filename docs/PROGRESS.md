# Sentinel — Progress Tracker

| Phase | Name | Status | Notes |
|---|---|---|---|
| 0 | Foundation & tooling | Complete | CI green on main (PR #1) |
| 1 | Core backend & logging | Complete | 205 backend tests; JSON logs + redaction; Alembic baseline; echo tool |
| 2 | Identity, RBAC & audit | Complete | 308 backend tests (267 unit + 41 integration); merged (PR #11) |
| 3 | Frontend shell | Complete locally, awaiting CI | 129 vitest tests; branch `feat/phase-3-frontend-shell`; audit viewer UI included |
| 4 | Client-side utilities | Not started | |
| 5 | Task infra & DNS | Not started | ADR needed: async tools inside Celery (event loop per process) |
| 6 | Scope policy & port scanner | Not started | Include the infra hard denylist + `lab` network |
| 7 | Header & TLS checker | Not started | Prototype httpx IP pinning with `sni_hostname` first |
| 8 | Threat intel | Not started | Stretch scope: two providers fully, third optional |
| 9 | Network diagnostics | Not started | Stretch. Traceroute best-effort on Docker Desktop |
| 10 | Log analyzer | Not started | Stretch |
| 11 | File integrity monitor | Not started | Stretch. Demo on a named volume, not a Windows bind mount |
| 12 | Playbook engine | Not started | |
| 13 | Reporting & export | Not started | |
| 14 | Observability & polish | Not started | Observability profile optional |

## MVP cut line

**Core demo:** Phases 0–7, 12, 13 (DNS → ports → headers/TLS → playbook → PDF report).
**Stretch:** Phases 8–11. **Optional:** the observability parts of Phase 14.

## Kickoff decisions (2026-10-01)

React 19, Node 24, TypeScript 6.0, `redis:7.4-alpine`, Python 3.12 inside the
containers. See `docs/adr/0001-architecture-and-stack.md`.

## Open items carried forward

- Starlette now warns that TestClient on `httpx` is deprecated in favour of
  `httpx2` (pydantic org). Decide before Phase 7, where httpx becomes a runtime dependency.
- Audit export to CSV/JSON (03-logging-audit.md section 6) needs a server endpoint that
  records `audit.exported`. Deferred to Phase 13 with the other exporters.
- After a frontend dependency change, refresh the `frontend_node_modules` volume:
  `docker compose exec frontend npm ci` (rebuilding the image alone does not).
- Phase 5: WebSocket auth (T12) and `useRunStatus` build on the Phase 3 API client.
- Existing dev volumes need the test DB once:
  `docker compose exec postgres sh /docker-entrypoint-initdb.d/02-test-db.sh`.
- The access-log route template relies on a FastAPI 0.14x internal (ADR 0002). A test pins it.
- Dependabot now ignores semver-major image updates (docker, docker-compose). Close the
  already-open Postgres 18 / Redis 8 / Node 26 PRs on GitHub.
- LICENSE copyright holder (`Anshuman-Singh-14`) needs confirming by the repo owner.
- The repo lives in OneDrive. Moving it to a non-synced path is recommended.

## Phase 3 log

- **Dependencies (exact pins):** `react-router` 8.4.0, `@tanstack/react-query` 5.104.1,
  `lucide-react` 1.49.0, dev `@testing-library/user-event` 14.6.7. See ADR 0004.
- **API client (`src/lib/api`):**
  - Same-origin paths only, a timeout on every request and `redirect: "error"`.
  - CSRF echo on every write.
  - Typed `ApiError` built from the error envelope.
  - Single-flight refresh with a Web Locks cross-tab mutex, and a session-expiry event.
- **Auth:**
  - `/auth/me` query, login page, `RequireAuth` (user published via context) and
    `RequireRole`.
  - Open-redirect-safe `?next=`, account page with password change, logout.
  - The query cache is cleared whenever the identity changes.
- **Shell:**
  - Sidebar built from the frontend manifest plus `GET /tools` (local tools listed as
    "soon"; unknown backend tools get a fallback icon).
  - Top bar with the user, role, an admin alerts bell and sign-out.
  - Status area polling `/health`, a skip link and a mobile drawer.
- **Design system:**
  - Primitives: `Card`, `Badge`, `SeverityBadge`, `Button`, `TextField`, `DataTable`,
    `JsonViewer`, `Tabs`, `Toast`, `Drawer` and `Spinner`.
  - Tokens in `index.css`, with a contrast test enforcing WCAG AA.
- **Pages:** dashboard, tool page (descriptor and parameter schema), account, not-found,
  route error, and the admin audit viewer (filters, keyset paging, detail drawer, chain
  verification, alerts with acknowledge).
- **Docs:** ADR 0004, threat-model rows T33–T37, and T9 updated.
- **Deviation:** `credentials: "same-origin"` instead of ADR 0003's `"include"`. It sends the
  same cookies for relative URLs and is stricter.
- **Local acceptance (2026-10-02):**
  - 129 vitest tests pass; eslint, prettier and tsc are clean; `npm audit` reports 0
    vulnerabilities.
  - The production build has no inline scripts or styles, so the nginx CSP still holds.
  - Vite dev server: every module transforms. Through the proxy, login → `/me` → `/tools`
    works, verify without CSRF is rejected and with CSRF returns 200, refresh rotates,
    logout returns 204, and `/me` afterwards returns 401.

## Phase 2 log

- **Data model:** `users`, `sessions`, `audit_events` and `security_alerts` in migration 0002.
  `audit_events` is INSERT/SELECT-only for `sentinel_app`, with UPDATE/DELETE/TRUNCATE
  triggers and an `id` that is `GENERATED ALWAYS`.
- **Audit:** `AuditService` with a SHA-256 hash chain kept linear by an advisory lock.
  Details are redacted before hashing. A failed audit write fails closed. The chain is
  verified in batches by `POST /admin/audit/verify`.
- **Alerts:** rules for failed-login bursts, refresh-token reuse and integrity failure.
  Sinks write a WARNING log line and a `security_alerts` row.
- **Auth:**
  - Argon2id hashing (threaded, concurrency capped) and a NIST-style password policy.
  - Opaque hashed tokens in `__Host-`/`__Secure-` cookies.
  - Refresh rotation with reuse detection.
  - Lockout with exponential backoff, plus a per-IP Redis rate limit.
  - Session-bound CSRF and Origin checks.
  - No user enumeration.
- **RBAC:** `require_viewer`, `require_analyst` and `require_admin`. Denials are audited
  as `auth.access.denied`, an addition to the spec's taxonomy. `GET /tools` now needs viewer.
- **Admin API:** users (create, role change, disable/enable), sessions (list, revoke),
  audit (filtered keyset listing, verify) and alerts (list, acknowledge).
- **CLI:** `python -m app.cli create-admin`, which reads the password from a prompt or stdin.
- **Tests and CI:**
  - Compose `test` profile using a separate `sentinel_test` database and Redis DB 15.
  - CI runs the integration tests plus a CLI-to-login smoke test.
- **Docs:** ADR 0003 and threat-model rows T24–T32 (T13 now done).
- **Deviations (recorded in ADR 0003):** a Redis counter instead of slowapi, no `roles`
  table, opaque tokens instead of JWTs, and the extra `auth.access.denied` and
  `user.enabled` actions.
- **Local acceptance (2026-10-02):**
  - 308 tests pass in the test profile; ruff, mypy and bandit are clean.
  - Migration upgrade → downgrade → upgrade plus `alembic check` is clean.
  - Browser-style smoke test through the Vite proxy: login cookies have the correct
    flags, CSRF is enforced, verify works, and logout invalidates the session.

## Phase 1 log

- Config split by consumer: `LoggingSettings` / `Settings` (api, worker) / `MigrationSettings` (migrate only).
- structlog pipeline for every logger; JSON in non-dev; standard + system fields on every line.
- Redaction processor (keys, patterns, scoped entropy, truncation, traceback tail) with 50+ security tests.
- Request-ID middleware (UUIDv7, validated incoming IDs, echoed header), route-template access log,
  trusted-proxy client IP, Celery header propagation.
- Error hierarchy and handlers; last-resort 500 with request ID; validation errors never echo input.
- Async SQLAlchemy engine/session; Alembic (async env, baseline 0001); one-shot `migrate` service.
- Translation Engine core: `ToolResult`/`Finding` schemas, `BaseTool` (metadata validated at
  definition), registry + discovery + catalogue, in-process runner, CVSS v3.1 severity helpers,
  YAML knowledge base. Echo tool and `GET /api/v1/tools`.
- CI: migration round trip + `alembic check`, app-role DDL denial, JSON-log check for api and worker.
- Docs: ADR 0002, threat model T15 and T18–T23.
- Local acceptance re-run (2026-10-01): 205 tests pass; ruff, mypy, bandit clean; migration
  upgrade → downgrade → upgrade + `alembic check` clean; JSON logs carry `request_id` on every line;
  `GET /api/v1/tools` lists `echo`. Remaining: green CI on the PR, then merge to `main`.

## Phase 0 log

- Repo restructured: specs moved to the root, placeholder `src/` removed.
- Backend: FastAPI factory, `/health` (liveness), `/ready` (Postgres + Redis, 2 s timeouts, 503 naming the failed component), security headers, strict CORS, minimal settings, Celery app (JSON-only, time limits, three queues, `sentinel.ping`).
- Frontend: Vite + React 19 + Tailwind 4 placeholder calling `/health` through the dev proxy, and an ESLint ban on `dangerouslySetInnerHTML`.
- Infra: compose with internal/edge networks, localhost-only ports, non-root and cap-dropped app containers, health checks on all five services, Postgres owner/app role split with a statement timeout.
- Tooling: pre-commit (ruff, mypy, bandit, gitleaks, prettier, eslint), GitHub Actions (backend, frontend, gitleaks, compose smoke), Dependabot.
- Docs: ADR 0001, threat-model skeleton.
