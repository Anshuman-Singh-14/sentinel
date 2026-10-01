# ADR 0002 — Structured logging with mandatory redaction

- **Status:** Accepted
- **Date:** 2026-10-01
- **Phase:** 1

## Context

Sentinel handles credentials (user passwords, provider API keys, DB/Redis
DSNs) and hostile data (banners, headers, uploaded logs). Logs are copied,
shipped and read by people who should never see those secrets. Operators also
need to trace one action across the API, the worker and the database.

## Decision

1. **One pipeline for every record.** structlog renders all logs, and stdlib
   loggers (uvicorn, celery, sqlalchemy, alembic, httpx) are routed through
   `structlog.stdlib.ProcessorFormatter` with the same processor chain. Even
   uvicorn's `--reload` supervisor gets that formatter via `--log-config`, and
   Celery's stdout banner is turned off with `--quiet`. The result is one JSON
   object per line, everywhere, and no output path that skips redaction.

2. **Redaction is a processor, not a convention.** It is the last step before
   rendering, so callers cannot forget it. It works in three layers:
   - **Key names** (`password`, `authorization`, `api_key`…) mask the whole value, recursively.
   - **Value patterns** (JWT, Bearer/Basic, `user:pass@` in URLs, AWS, GitHub,
     Slack, OpenAI-style and Google keys, PEM private keys, and `key=value` /
     `"key": "value"` pairs) mask inside any string.
   - **High-entropy tokens** are masked only inside credential-bearing fields
     (headers, query, payload…). Hex digests top out at 4.0 bits/char, below
     the 4.2 threshold, so SHA-256 results survive.

3. **Exceptions are rendered before redaction.** A traceback quoting a DSN is
   masked, and long tracebacks are cut from the front so the exception line
   survives. The trade-off is losing coloured tracebacks in dev.

4. **Noisy or risky library logs are capped** at WARNING:
   - uvicorn's access log, which logs raw paths and query strings
   - `sqlalchemy.engine`, which logs bound parameters at INFO
   - `httpx`/`httpcore`, which log full outbound URLs at INFO

   Our own access log records the **route template**, never the raw path.

5. **Correlation.** `request_id` is a UUIDv7 (time-ordered), or a caller value
   matching `^[A-Za-z0-9_-]{1,64}$`. Anything else is replaced, which blocks
   log injection through the header. It is stored in contextvars, echoed as
   `X-Request-ID`, and carried into Celery through a message header, where the
   worker re-validates it and binds it alongside `celery_task_id`.

6. **Stable schema.** Every line has `timestamp, level, event, logger, service,
   hostname, process_user, pid, app_version, environment, request_id, user_id,
   run_id`. Fields that don't apply are null, never missing.

## Consequences

- Redaction errs towards over-masking. For example, `refresh_interval` would
  be masked, because it contains `refresh`. That is preferable to a leak.
  `session_id`, `token_type` and `token_count` are explicitly allowlisted.
- Values are masked, not fingerprinted. A safe fingerprint needs a keyed HMAC
  and is deferred until there's a concrete need.
- The full route template is read from FastAPI's per-request routing context
  (`scope["fastapi"]["effective_route_context"]`), an internal of FastAPI
  0.14x. It is read defensively, and a test pins the expected value, so an
  upgrade that moves it fails CI instead of silently logging the wrong thing.
- The test suite in `tests/security/test_redaction.py` must grow with every
  new secret type (provider keys in Phase 8, auth tokens in Phase 2).
