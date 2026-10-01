# ADR 0001 — Architecture and technology stack

- **Status:** Accepted
- **Date:** 2026-10-01
- **Phase:** 0

## Context

Sentinel runs security tools that are I/O-bound and sometimes slow: port scans,
TLS handshakes, third-party intel APIs and multi-step playbooks. Users need live
progress, every action must be attributable, and the whole platform has to start
with one command for a capstone demo. It must never execute shell commands.

## Decision

| Concern | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 (Python 3.12) | Native async for I/O-bound tools. Pydantic gives strict boundary validation and generates the JSON Schemas the frontend renders as forms. |
| Background work | Celery 5 on Redis | Scans outlive an HTTP request. A separate worker isolates heavy or long jobs from the API, enforces soft/hard time limits and supports revocation. Separate queues (`default`, `scans`, `intel`) stop slow scans from starving quick lookups. |
| Realtime | WebSocket + Redis pub/sub | Workers publish progress and the API relays it. No polling, and no client connections to workers. |
| Database | PostgreSQL 16 | Transactional integrity, JSONB for findings and audit details, row triggers and role grants for the append-only audit trail. |
| Frontend | React + Vite + TypeScript + Tailwind | Typed UI, fast dev loop, and the client-side tools run fully in the browser (Web Crypto). |
| Packaging | Docker Compose | One command starts the whole stack, and the network topology itself enforces isolation. |
| Python deps | uv with a lockfile | Reproducible, hash-pinned installs; fast image builds. |

Deviations from the original spec, all decided at kickoff:

- **React 19** instead of 18. 19 is current, the ecosystem targets it, and no spec requirement depends on 18.
- **Node 24** instead of 20, because Node 20 reached end of life in April 2026.
- **TypeScript 6.0**, the newest version typescript-eslint supports.
- **redis:7.4** (BSD) instead of Redis 8 (AGPL/RSAL/SSPL), to avoid licensing questions.
- **nginx-unprivileged** for the production frontend image, so it runs as non-root without extra capabilities.

### Zero shell execution

The application never spawns processes (`subprocess`, `os.system`, `eval`,
`exec`, `pickle`). Network work uses `socket`/`asyncio`, `dnspython`, `icmplib`,
`httpx` and `ssl`. Shelling out to tools like `nmap` would make argument
injection a constant risk and would tie behaviour to whatever binaries happen to
be installed. Pure-library implementations are testable, portable, and can be
bounded with timeouts and concurrency limits.

Three things enforce this: ruff's `S` rules, `bandit` in CI, and
`tests/security/test_forbidden_calls.py`, an AST scan that fails the test run.
Docker `HEALTHCHECK` commands are container orchestration, not application code,
so they are outside the rule.

## Consequences

- There are more moving parts (api, worker, redis, postgres, frontend) than in a
  monolith, which costs memory and startup time on a laptop.
- Async tool code has to run inside synchronous Celery tasks. Phase 5 decides the
  event-loop strategy (one loop per worker process) in its own ADR.
- Some tooling capability is lost on purpose. There are no SYN scans and no OS
  fingerprinting, which is consistent with Sentinel being defensive and educational.
