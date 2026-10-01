# 01 — Architecture

## Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Frontend | React 18, Vite, TypeScript, Tailwind CSS, Lucide icons, React Router, TanStack Query | Dark cyberpunk / industrial SOC aesthetic. Accessible contrast (WCAG AA) despite the dark theme |
| API | Python 3.12, FastAPI, Pydantic v2, pydantic-settings | Fully async where I/O bound |
| Workers | Celery 5 with Redis broker | Long-running and resource-heavy jobs |
| Realtime | FastAPI WebSockets + Redis pub/sub | Workers publish progress; API relays to clients |
| Database | PostgreSQL 16, SQLAlchemy 2.0 (async), asyncpg, Alembic | Migrations mandatory |
| Logging | structlog (JSON), contextvars | See `03-logging-audit.md` |
| Rate limiting | slowapi (Redis backend) | Per-user and per-IP |
| HTTP client | httpx (async) | Timeouts and redirect limits always set |
| Reports | ReportLab (PDF), stdlib csv/json | HTML templates optional later |
| Deployment | Docker, Docker Compose | `docker compose up` starts everything |
| Quality | ruff, mypy, bandit, pip-audit, pytest, pytest-asyncio, eslint, prettier, vitest, pre-commit, GitHub Actions | |

## Services (docker-compose)

- `frontend` — Vite dev server (dev) / nginx serving static build (prod profile)
- `api` — FastAPI via uvicorn
- `worker` — Celery worker (separate queues: `default`, `scans`, `intel`)
- `beat` — Celery beat (optional, added in the FIM phase for scheduled integrity checks)
- `redis` — broker, result backend, pub/sub, rate-limit store. Password protected
- `postgres` — primary datastore

Postgres and Redis are on an internal network and **not** published to host ports by default. All app containers run as non-root with health checks.

## Request and task flow

```
React ─► POST /api/v1/tools/{tool_id}/runs ─► FastAPI (auth, validate, scope check, audit)
                                                 │
                                                 ├─► ToolRun row (QUEUED) in Postgres
                                                 └─► Celery task (carries run_id, user_id, request_id)
                                                          │
                                   Worker executes tool ──┤ publishes progress to Redis channel run:{run_id}
                                                          │
React ◄── WebSocket /ws/runs/{run_id} ◄── FastAPI relays ─┘
                                                 └─► final ToolResult persisted, status COMPLETED/FAILED
```

Run states: `QUEUED → RUNNING → COMPLETED | FAILED | CANCELLED | TIMED_OUT`. Cancellation uses Celery revoke plus a cooperative cancel flag the tool checks between work units.

Short tools (e.g. a single DNS lookup) may still go through Celery for uniformity; that is preferred over special cases.

## Modular folder structure

```
sentinel/
├── CLAUDE.md
├── README.md
├── docker-compose.yml
├── .env.example
├── .pre-commit-config.yaml
├── .github/workflows/ci.yml
├── docs/
│   ├── PROGRESS.md
│   ├── spec/                      # these specification files
│   ├── adr/                       # architecture decision records
│   └── threat-model.md
│
├── backend/
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── alembic/
│   └── app/
│       ├── main.py                # app factory, middleware, router mounting
│       ├── config.py              # pydantic-settings
│       ├── core/
│       │   ├── logging/           # structlog config, processors, redaction, context
│       │   ├── audit/             # audit service, hash chain, models, router
│       │   ├── auth/              # users, passwords, tokens, RBAC dependencies
│       │   ├── security/          # validators, scope policy, SSRF guard, path guard
│       │   ├── tasks/             # celery app, base task, progress publisher, cancel
│       │   ├── realtime/          # websocket manager, redis pubsub relay
│       │   ├── errors.py          # exception types → structured responses
│       │   └── ratelimit.py
│       ├── db/
│       │   ├── base.py
│       │   ├── session.py
│       │   └── models/            # shared models: ToolRun, Finding, Report...
│       ├── engine/                # the Educational Translation Engine
│       │   ├── schemas.py         # ToolResult, Finding, Severity
│       │   ├── base_tool.py       # BaseTool abstract class
│       │   ├── registry.py        # tool registry + discovery
│       │   ├── severity.py        # documented severity criteria helpers
│       │   └── knowledge/         # explanation/remediation text (YAML), versioned
│       ├── tools/                 # ONE PACKAGE PER TOOL
│       │   ├── dns_lookup/
│       │   │   ├── __init__.py    # registers the tool
│       │   │   ├── schemas.py     # input params model
│       │   │   ├── service.py     # pure async logic, no framework imports
│       │   │   ├── translator.py  # raw → Findings
│       │   │   └── tests/
│       │   ├── port_scanner/
│       │   ├── header_tls/
│       │   ├── threat_intel/
│       │   │   └── providers/     # abuseipdb.py, virustotal.py, shodan.py
│       │   ├── net_diag/
│       │   ├── log_analyzer/
│       │   │   └── parsers/       # auth_log.py, nginx.py
│       │   └── fim/
│       ├── playbooks/
│       │   ├── engine.py
│       │   ├── schemas.py
│       │   └── definitions/       # YAML/JSON playbook definitions
│       ├── reports/
│       │   ├── service.py
│       │   └── exporters/         # pdf.py, json.py, csv.py, text.py
│       └── api/v1/                # thin routers: tools, runs, playbooks, reports, auth, admin
│
├── frontend/
│   ├── Dockerfile
│   └── src/
│       ├── app/                   # router, providers, layout shell
│       ├── components/ui/         # design-system primitives
│       ├── features/
│       │   ├── auth/
│       │   ├── dashboard/
│       │   ├── runs/              # run status, websocket hook, result viewer
│       │   ├── playbooks/
│       │   ├── reports/
│       │   ├── audit/             # admin audit log viewer
│       │   └── tools/
│       │       ├── registry.ts    # frontend tool manifest (drives nav)
│       │       ├── local/         # client-side tools, one folder each
│       │       └── remote/        # backend tool forms, one folder each
│       ├── lib/                   # api client, ws client, crypto helpers
│       └── types/
│
└── tests/
    ├── integration/               # cross-service tests against compose stack
    └── security/                  # SSRF, traversal, injection, authz, redaction tests
```

Per-tool unit tests live beside the tool; cross-cutting tests live in `/tests`.

## Tool plugin contract

```python
class BaseTool(ABC, Generic[ParamsT]):
    tool_id: ClassVar[str]              # "dns_lookup"
    name: ClassVar[str]                 # "DNS & Domain Intelligence"
    version: ClassVar[str]              # semver, stored with every result
    category: ClassVar[ToolCategory]    # RECON, WEB, INTEL, DIAGNOSTIC, FORENSIC
    params_model: ClassVar[type[ParamsT]]
    is_active: ClassVar[bool]           # sends traffic to targets → scope check required
    required_role: ClassVar[Role]
    queue: ClassVar[str] = "default"
    soft_time_limit: ClassVar[int]
    hard_time_limit: ClassVar[int]

    async def run(self, params: ParamsT, ctx: ToolContext) -> RawOutput: ...
    def translate(self, raw: RawOutput, params: ParamsT) -> list[Finding]: ...
```

`ToolContext` provides: `run_id`, `report_progress(pct, message)`, `is_cancelled()`, a bound logger, and settings. The framework (not each tool) handles persistence, audit, timing, error wrapping and WebSocket publishing. A single generic endpoint `POST /api/v1/tools/{tool_id}/runs` dispatches via the registry; `GET /api/v1/tools` returns the catalogue with JSON Schemas so the frontend can render forms.

## Standard result schema

```json
{
  "run_id": "uuid",
  "tool_id": "header_tls",
  "tool_name": "HTTP Security Header & TLS Checker",
  "tool_version": "1.0.0",
  "target": "example.com",
  "initiated_by": "analyst01",
  "status": "COMPLETED",
  "started_at": "2026-09-30T19:00:00Z",
  "completed_at": "2026-09-30T19:00:04Z",
  "duration_ms": 4120,
  "summary": { "total": 6, "by_severity": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 1, "INFO": 2 } },
  "findings": [
    {
      "finding_id": "uuid",
      "item": "Strict-Transport-Security (HSTS)",
      "category": "HTTP_HEADERS",
      "status": "MISSING",
      "severity": "MEDIUM",
      "severity_rationale": "Missing HSTS on an HTTPS site permits downgrade/SSL-stripping on first visit (OWASP Secure Headers Project).",
      "confidence": "HIGH",
      "explanation": "HSTS tells browsers to only use HTTPS for this site...",
      "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`...",
      "evidence": { "response_headers_checked": ["..."] },
      "references": ["https://owasp.org/www-project-secure-headers/", "CWE-319"],
      "raw_data": {}
    }
  ],
  "errors": [],
  "raw_data": {}
}
```

- `severity`: `INFO | LOW | MEDIUM | HIGH | CRITICAL`
- `status` per finding: `PASS | FAIL | MISSING | WEAK | DETECTED | CHANGED | ADDED | REMOVED | ERROR | INFO`
- `confidence`: `LOW | MEDIUM | HIGH` (important for banner-based CVE guesses)
- Severity must come from documented criteria in `engine/severity.py` (CVSS v3.1 bands for CVEs: 0.1–3.9 LOW, 4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0–10.0 CRITICAL; OWASP/CWE/NIST guidance for configuration findings). Every finding carries a `severity_rationale` and at least one reference where one exists.
- Explanation and remediation text lives in versioned YAML under `engine/knowledge/`, not scattered across code, so it can be reviewed and improved in one place.

## Core database models (initial)

`users`, `roles`, `sessions/refresh_tokens`, `tool_runs`, `findings`, `playbook_runs`, `playbook_steps`, `fim_baselines`, `fim_baseline_entries`, `reports`, `audit_events`, `provider_configs` (metadata only; secrets stay in env).
