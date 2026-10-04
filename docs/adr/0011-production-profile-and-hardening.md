# ADR 0011 — Production profile, security pass and capstone polish

- **Status:** Accepted
- **Date:** 2026-10-04
- **Phase:** 14

## Context

Phase 14 (05-phases.md): an optional observability profile, a production
compose profile (nginx, no dev servers), a full security test pass, a load
test of concurrent runs, a README with architecture, setup, screenshots,
security design and ethics statement, and the final threat model.
Acceptance: a fresh clone reaches a working demo with `docker compose up`, by
following the README, in under 10 minutes.

## Decisions

### 1. Production is an override file, not a profile

`docker-compose.prod.yml` is layered on `docker-compose.yml`
(`docker compose -f docker-compose.yml -f docker-compose.prod.yml up`).

Compose profiles can only add or remove services. They cannot change an
existing service's image, command, mounts or ports, and the production stack
needs exactly those changes for the same services. Two copies of every
service in one file would drift. The override uses Compose's `!reset` and
`!override` tags (Compose v2.24+) to remove the dev bind mounts and ports
rather than merge them.

What it changes:

| | Development | Production |
|---|---|---|
| Backend image | `dev` (tools, source bind-mounted, `--reload`) | `runtime` (code baked in, root-owned, no dev tools) |
| Web app | Vite dev server on 5173 | Static build served by `nginx-unprivileged`, which proxies `/api`, `/health`, `/ready` and `/ws` |
| Published ports | API 8000 and frontend 5173 | nginx 8080 only |
| Root filesystem | Writable | Read-only, with a tmpfs for `/tmp` |
| `ENVIRONMENT` | `development` | `production`: JSON logs, no `/docs`, HSTS on API responses, `COOKIE_SECURE=false` refused |
| API processes | 1 (reload) | 2 uvicorn workers |

### 2. Trust `X-Forwarded-For` from nginx's address only

nginx gets a pinned address (`SENTINEL_FRONTEND_IP`, default `10.231.1.10`),
and the API's `TRUSTED_PROXIES` is that single address.

The first version trusted the whole edge subnet. A live check showed why
that is wrong: the subnet contains Docker's gateway, so the audit log
recorded nginx's own address as the client. With the pinned /32 the audit
log records the real peer, and nothing else on the network can forge the
header.

### 3. Security headers: no duplicates, and Sentinel passes its own checker

nginx adds its strict CSP and the companion headers only to the static app
(`location /`). API responses pass through with the API's own headers, which
are stricter (`default-src 'none'`).

Adding nginx's headers to API responses as well sent every header twice
(`nosniff, nosniff`). Sentinel's own header checker reported that as
missing, and some parsers do too. The API also gained `Permissions-Policy`,
the one LOW finding the checker reported against it.

`scripts/self_header_check.py` runs the built-in checker against the live
production front end, and CI fails on any finding above INFO. A unit test
does the same for the API in production mode.

### 4. WebSockets under the strict CSP

`connect-src 'self'` covers same-origin `ws:` and `wss:` under CSP Level 3.
Live run updates were verified under the production policy in Chromium and
Firefox with Playwright: the socket connected, frames were received, and
there were no violations.

WebKit could not be checked this way, because it does not send `Secure`
cookies to `http://localhost`, so it cannot sign in over plain HTTP.
Production deployments terminate TLS in front of nginx, which removes that
limitation.

### 5. Full security pass

- **New in `tests/security/`:**
  - `test_authz_matrix.py` declares the minimum role of every route. A route
    missing from the table fails the build. Each protected route is checked
    for 401 when anonymous, and for 403 (audited) for each lower role:
    41 routes, 34 denial cases.
  - `test_security_headers.py` checks the headers on success and error
    responses, and runs the production API against the built-in checker.
- **Already covered:** SSRF and scope bypass, redaction, CSV injection,
  forbidden calls, rate limits (integration), and append-only grants
  (integration).
- **Path traversal:** not applicable yet; it arrives with the first file tools
  (T16, Phases 10 and 11).
- **Supply chain:** `pip-audit` and `npm audit` are clean.

### 6. Cookie-less refresh probes are no longer audited

The SPA asks for the session on every page load. For an anonymous visitor
that ends in a refresh request with no refresh cookie at all. Since Phase 2
each one wrote an `auth.token.refresh` FAILURE row, so the audit log of a
quiet system filled with noise. The screenshots made this obvious.

This contradicted the threat model's own rule that unauthenticated 401s are
not audited. Now:

- a missing cookie is a plain 401;
- a present but malformed cookie is still audited (`malformed_token`);
- unknown, reused and expired tokens are audited as before;
- the per-IP refresh rate limit still applies first.

### 7. Load test as a script, run against the real stack

`scripts/load_test.py` runs inside the api container, so nothing is
installed on the host. It:

1. creates temporary analysts;
2. drives concurrent runs through the real quotas and workers, retrying on
   429 as a client should;
3. exports a report per user;
4. verifies the audit chain;
5. disables its users.

It exits non-zero on any 5xx, an incomplete run or a broken chain.

Results on Docker Desktop, production profile:

| Load | Runs completed | Quota 429s (retried) | Create run p50 / p95 | 5xx | Chain verified |
|---|---|---|---|---|---|
| 6 users × 15 runs | 90/90 | 19 | 31 / 61 ms | 0 | ok |
| 8 users × 30 runs | 240/240 | 126 | 36 / 62 ms | 0 | ok (1,221 events) |

Throughput is bounded by the per-user quotas (3 active runs, 20 per minute)
and by the worker's concurrency of 2, by design. CI runs a small
configuration (3 users × 5 runs) as part of the production smoke job.

### 8. Fresh-clone bootstrap

`scripts/init-env.sh` (POSIX sh) and `scripts/init-env.ps1` (Windows)
create `.env` with a fresh 48-hex-character secret for every `CHANGE_ME`,
read from the OS CSPRNG. They refuse to overwrite an existing `.env`, and
the shell version creates it owner-readable. The README's 10-minute demo
is: clone, run the script, `docker compose --profile lab up --build -d
--wait`, `create-admin`, and a guided walkthrough.

### 9. Deferred, with reasons

- **Observability profile (OpenTelemetry, Prometheus, Loki):** the spec marks
  it optional, and it would add several dependencies and services.
  Structured JSON logs with request IDs, shippable by any Docker logging
  driver, cover the capstone's needs. Revisit after Phases 8–11.
- **Report retention:** reports are kept indefinitely. The app role cannot
  delete them, by design. Purging is an owner-role maintenance task that
  belongs in the deployment's data policy.
- **TLS:** left to the deployment, in front of nginx. The README says so.

## Consequences

- Two compose invocations to remember. The README and CLAUDE.md list both.
- `scripts/` holds operational scripts that run inside the containers. They
  are checked by ruff with the backend configuration.
- Threat model rows T64–T69. T14 (resource exhaustion) moved from Partial
  to Done.
