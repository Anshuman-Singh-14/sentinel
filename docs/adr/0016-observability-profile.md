# ADR 0016: Optional observability profile

- **Status:** Accepted
- **Date:** 2026-10-05
- **Context:** Phase 14's optional part, deferred in ADR 0011 section 9 until
  Phases 8–11. Issue #32. Reserved numbers: ADR 0016, threats T85–T89.

## Context

03-logging-audit.md section 8 lists three optional items:

- OpenTelemetry traces for API to worker spans;
- log shipping to Loki/Grafana "via Docker logging driver" (compose profile
  `observability`);
- Prometheus metrics for request latency, task durations, queue depth and
  failures by tool.

The constraints are CLAUDE.md's: minimal pinned dependencies, no secrets in
logs, timeouts and limits, and nothing that weakens the default stack. A
plain `docker compose up` must behave exactly as before.

## Decisions

### 1. Metrics: one small dependency, one protected endpoint

- **Dependency:** `prometheus-client` 0.26.0. It is pure Python with no
  transitive dependencies.
- **Endpoint:** `GET /metrics` on the API, outside `/api/v1`, like `/health`.
  - **Off by default.** It is enabled only when `METRICS_TOKEN` is set (at
    least 32 characters). When disabled, the route answers 404, so a scanner
    learns nothing.
  - **Authentication:** `Authorization: Bearer <METRICS_TOKEN>`, compared in
    constant time. A failure returns 401 with a generic body. Prometheus reads
    the token from a file it writes at start, so it never appears in its
    config or process list.
  - **Not exposed through production nginx,** which only proxies `/api`,
    `/health`, `/ready` and `/ws`.
- **HTTP metrics:** request count and a latency histogram by method, **route
  template** and status class, recorded by the existing access-log middleware.
  - Route templates (`/api/v1/runs/{run_id}`) keep cardinality bounded and
    keep identifiers out of labels, the same rule as the access log
    (ADR 0002).
  - Production runs two uvicorn workers, so the client's multiprocess mode
    stores values in a private directory (`/tmp/sentinel-metrics`, tmpfs in
    production) and a scrape sums every worker.
- **Business metrics** are read from Postgres and Redis at scrape time, not
  instrumented in the worker:
  - `sentinel_tool_runs{tool_id,status}`;
  - `sentinel_tool_run_duration_seconds_sum` and `_count` per tool;
  - `sentinel_tool_run_duration_p95_seconds` over the last hour;
  - `sentinel_playbook_runs{status}` and `sentinel_reports{status}`;
  - `sentinel_queue_depth{queue}`;
  - `sentinel_security_alerts{state}`;
  - `sentinel_audit_events` (the last sequence number, so no table scan).
  - Run history is never deleted (no DELETE grant), so counts by terminal
    status only grow and `increase()` works on them.
  - Nothing is lost when a worker restarts, there is no per-process state in
    workers, and the metrics match what the UI shows.
  - Each query is a small aggregate, bounded by the statement timeout.

### 2. Logs: shipped from Docker's own log files, without the Docker socket

- **How:** Grafana Alloy tails Docker's JSON log files
  (`/var/lib/docker/containers`, mounted read-only) and pushes them to Loki.
  The app already writes one JSON object per line with `service`, `level`,
  `event` and `request_id`, already redacted (ADR 0002). Alloy promotes
  `service` and `level` to labels.
- **Rejected: the Loki Docker logging driver,** which the spec names. It is a
  host plugin (`docker plugin install`) that changes how every container
  logs, isn't available on every Docker Desktop, and makes `docker logs`
  depend on Loki being up.
- **Rejected: discovery through `/var/run/docker.sock`.** The socket is root
  on the host.
- **Trade-off:** Alloy runs as root inside its container, with all
  capabilities dropped, a read-only root filesystem and no network beyond the
  observability network, so that it can read root-owned log files. It can
  read every container's stdout, which here holds only redacted application
  logs and service logs.
- **JSON required:** set `LOG_FORMAT=json` with the profile (documented).
  Console-format lines are still shipped, just without labels.

### 3. Traces: deferred, with reasons

OpenTelemetry would add about ten packages, including protobuf or gRPC
exporters and per-library instrumentations (FastAPI, Celery, SQLAlchemy,
httpx), plus a collector service. The correlation the spec is after already
exists:

- one `request_id` ties the HTTP request, the Celery task (message header),
  every log line and every audit event (ADR 0002);
- Loki queries by `request_id` therefore show the API-to-worker path of a run.

Traces are recorded as future work, not built.

### 4. The `observability` compose profile

| Service | Image (pinned) | Network | Host port |
|---|---|---|---|
| `prometheus` | `prom/prometheus:v3.15.0` | `obs`, `edge` (to scrape the API) | none |
| `loki` | `grafana/loki:3.7.8` | `obs` | none |
| `alloy` | `grafana/alloy:v1.20.1` | `obs` | none |
| `grafana` | `grafana/grafana:13.2.3` | `obs`, `edge` | `127.0.0.1:3000` |

- **The `obs` network is internal** (no internet access). None of these
  services joins `internal`, so they cannot reach Postgres or Redis.
- **Hardening:** every service drops all capabilities and sets
  `no-new-privileges`. Prometheus, Loki and Grafana run as their images'
  non-root users.
- **Retention:** Prometheus 7 days, Loki 7 days. Data lives in named volumes.
- **Grafana:**
  - Datasources and a "Sentinel overview" dashboard are provisioned from files
    in `infra/observability/`.
  - Sign-up and anonymous access are off, and so are update checks and usage
    reporting (no phoning home from a security tool).
  - The admin password comes from `GRAFANA_ADMIN_PASSWORD`. Grafana refuses to
    start without one instead of falling back to `admin`/`admin`.
- **Secrets:** `.env.example` gains `METRICS_TOKEN=CHANGE_ME` and
  `GRAFANA_ADMIN_PASSWORD=CHANGE_ME`, so `run.py` and `init-env` generate them
  for new installs. An older `.env` without them keeps working: metrics stay
  off, and only Grafana refuses to start.
- **Usage:**
  `LOG_FORMAT=json docker compose --profile lab --profile observability up -d`,
  then open http://localhost:3000.

## Alternatives considered

- **Instrumenting Celery tasks with counters.** Workers are separate
  processes that restart, so counters would reset and need a push gateway or
  multiprocess files shared across containers. Reading the database is
  simpler and always matches the UI.
- **Serving metrics on a separate port.** That conflicts with multiple
  uvicorn workers binding one port, and a token on the existing app is
  simpler to reason about.

## Consequences

- A plain `docker compose up` is unchanged. The endpoint is off without a
  token, and the four services exist only under the profile.
- Adding a metric means adding a query in `app/core/metrics.py` and a panel
  in the dashboard JSON.
- Traces stay future work.
