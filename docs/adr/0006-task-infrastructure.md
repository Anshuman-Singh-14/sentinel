# ADR 0006 — Task infrastructure, live updates and the DNS tool

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 5

## Context

From Phase 5, tools run in Celery workers. Users watch runs live, can cancel
them, and see every outcome, including failures, as a structured result.
PROGRESS.md flagged one design question: how async tools run inside Celery's
synchronous tasks.

## Decisions

### 1. Run lifecycle and ordering

`POST /api/v1/tools/{tool_id}/runs` validates the request and then:

1. Inserts a `tool_runs` row (QUEUED) and records `tool.run.requested` in the
   **same transaction**.
2. Sends the Celery task **after** commit, so a worker never sees a run that
   does not exist. If sending fails, the run becomes FAILED (`dispatch_failed`),
   the failure is audited, and the client gets a 503.

The task message carries **only the run id**. The worker reads the validated
parameters from the database and validates them again, so a tampered broker
message cannot inject parameters.

Status changes are compare-and-set in SQL (`UPDATE … WHERE status = 'QUEUED'`):

- The worker claims QUEUED → RUNNING.
- A cancel of a queued run sets QUEUED → CANCELLED.
- Exactly one of them wins a race; a cancelled run is never started.

A redelivered message for a RUNNING run means the previous worker died
(`acks_late` with `reject_on_worker_lost`). That run is marked FAILED
(`worker_lost`), **not re-run**: repeating an active scan is a new action that
someone has to request.

### 2. One event loop per worker process

Tools, SQLAlchemy/asyncpg and the Redis client are async, but Celery tasks are
sync.

- `asyncio.run()` per task is wrong: it closes the loop after every task,
  while the cached connection pools stay bound to the dead loop.
- Each prefork child therefore lazily creates **one loop for its lifetime**
  (`app/core/tasks/loop.py`). A prefork process runs one task at a time.
- `get_redis()` rebinds when the running loop changes.
- If Celery's soft limit interrupts a task mid-await, `reset_loop()` abandons
  the loop and the clients bound to it, and the run is recorded as TIMED_OUT.

### 3. Time limits in layers

1. `asyncio.timeout(tool.soft_time_limit)` inside `execute_tool` ends the run
   gracefully as **TIMED_OUT**. This is the normal path.
2. Celery's soft limit is `hard_time_limit + 10 s`, the backstop for a tool
   that blocks the loop.
3. Celery's hard limit is `hard_time_limit + 20 s` and kills the process. The
   redelivery rule in section 1 then records `worker_lost`.

### 4. Cancellation

- **Queued:** a compare-and-set to CANCELLED, plus a best-effort
  `celery revoke`.
- **Running:** the API sets `cancel_requested_at` and a Redis flag. The tool
  polls the flag through `ctx.raise_if_cancelled()`, throttled to every
  0.5 s, between units of work.
- **Who may cancel:** only the requester or an admin; other attempts are
  audited.
- **Late cancel:** a run that finishes before it notices the flag keeps its
  real outcome.

Verified live: a DNS run cancelled at 5% ended CANCELLED, and a second cancel
returned 409.

### 5. Live updates: Redis pub/sub → WebSocket

- The worker publishes a JSON snapshot (status, progress, finding count) to
  `sentinel:run:{id}` on every change. Progress is written to the database at
  most once per second.
- `/ws/runs/{id}` subscribes **before** reading the database snapshot, so no
  update falls in the gap. It re-reads the database every 5 s, because
  pub/sub is best effort, and closes when the run ends or after 30 minutes.
- **Authentication (threat model T12):**
  - The Origin header must be in the allowlist. This blocks Cross-Site
    WebSocket Hijacking.
  - A single-use ticket is also required, obtained from
    `POST /runs/{id}/ws-ticket` (authenticated and CSRF-checked). The ticket
    is valid for 30 s, bound to one user and one run, stored hashed, and
    redeemed with `GETDEL`.
- **Frontend:**
  - `useRunStatus` loads the run over REST and merges socket events into the
    cache.
  - When an event reports a terminal status it refetches the full result.
  - If the socket fails it **falls back to polling** every 2 s.
- **CSP note:** the nginx policy `connect-src 'self'` covers same-origin
  `ws:`/`wss:` in CSP Level 3 browsers. This should be re-checked in
  Phase 14.

### 6. Quotas and limits

- 20 runs per user per minute (Redis limiter).
- At most 3 QUEUED/RUNNING runs per user, checked against a partial index.
- Stored raw output is capped at 1 MB; larger output is replaced by a notice.
- Every DNS query has a per-attempt timeout (3 s) and a lifetime (6 s), and
  the whole tool has a 30 s limit.

### 7. Fail-closed scope until Phase 6

Any tool with `is_active = True` is **refused** with `scope_denied`, and a
`tool.run.denied_scope` security event is recorded. Phase 6 replaces this with
the scope policy. Until then, an active tool added early cannot send traffic
anywhere.

### 8. Data model and grants (migration 0003)

- `tool_runs`:
  - The app role may SELECT, INSERT and UPDATE; there is **no DELETE**, so run
    history is evidence.
  - `username` is a snapshot, so attribution survives renames.
  - UUIDv7 ids make `id` the keyset pagination key.
- `findings`:
  - The app role may only SELECT and INSERT (write-once).
  - Findings are a table, not a JSON blob, so Phase 13 reports can query
    across runs.

### 9. Worker egress and the DNS tool

- **Egress:** the worker joins a new `egress` network. The API and the data
  stores stay egress-free.
- **Explicit resolvers:** the DNS tool uses explicit upstream resolvers
  (`DNS_NAMESERVERS`, default `1.1.1.1,9.9.9.9`). Docker's embedded resolver
  would answer for `postgres` and `redis`, turning the tool into an internal
  reconnaissance aid.
- **Domain validation:** input is IDNA-normalised and checked label by label
  (RFC 1123). Single-label names, IP literals, URLs and private or reserved
  suffixes are refused: `.internal`, `.local`, `.localhost`, `.arpa`,
  `.home.arpa`, `.test`, `.onion` and others.
- **Reverse lookups:** PTR lookups are only sent for public IPs.
- **Partial failures:** a single record type failing becomes a partial result
  with `errors[]`. If no resolver answers at all, the run FAILS with
  `provider_error`.
- **Findings** (texts in `engine/knowledge/dns.yaml`):
  - SPF: missing, multiple records, `+all`, neutral, OK.
  - DMARC: missing, invalid, `p=none`, `pct` below 100, enforced.
  - CAA: missing or present.
  - Dangling CNAMEs (apex and `www`), at HIGH severity with medium confidence.
  - Single name server or single provider.
  - Private IPs published in public DNS.
  - NXDOMAIN.
  - `resolved_ips` in the raw output is the hand-off point for Phase 12
    playbooks.

## Consequences

- **Dependency:** `dnspython` 2.8.0. No shell `dig` (CLAUDE.md rule 1).
- **Integration tests:** they call the worker's `execute_run` in-process on
  its own loop and engine. This covers claim, execute, persist, audit, quota,
  timeout, cancel, redelivery, the output cap, grants and the WebSocket
  ticket rules on real Postgres and Redis.
- **Local-tool isolation guard:** the Phase 4 static guard now ignores
  comments, so documentation that mentions an API is not flagged. A mutation
  check confirms that real code is still caught.
