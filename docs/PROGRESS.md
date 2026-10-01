# Sentinel — Progress Tracker

| Phase | Name | Status | Notes |
|---|---|---|---|
| 0 | Foundation & tooling | Complete | CI green on main (PR #1) |
| 1 | Core backend & logging | Complete, awaiting CI on PR | 205 backend tests; JSON logs + redaction; Alembic baseline; echo tool |
| 2 | Identity, RBAC & audit | Not started | DB roles already split (owner/app) in Phase 0 |
| 3 | Frontend shell | Not started | |
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
- slowapi vs a small Redis token bucket on `limits`: decide in Phase 2.
- The access-log route template relies on a FastAPI 0.14x internal (ADR 0002). A test pins it.
- Dependabot opened major-version PRs (Postgres 18, Redis 8, Node 26) that contradict the
  kickoff decisions. The Postgres 18 one fails CI (18 changed the data directory layout).
  Close them, or add `ignore` rules for semver-major on images.
- LICENSE copyright holder (`Anshuman-Singh-14`) needs confirming by the repo owner.
- The repo lives in OneDrive. Moving it to a non-synced path is recommended.

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
