# Sentinel — Progress Tracker

| Phase | Name | Status | Notes |
|---|---|---|---|
| 0 | Foundation & tooling | Complete | CI green on main (PR #1) |
| 1 | Core backend & logging | Complete | 205 backend tests; JSON logs + redaction; Alembic baseline; echo tool |
| 2 | Identity, RBAC & audit | Complete | 308 backend tests (267 unit + 41 integration); merged (PR #11) |
| 3 | Frontend shell | Complete (merged, PR #12) | 129 vitest tests; ADR 0004; audit viewer UI included |
| 4 | Client-side utilities | Complete (merged, PR #13) | 289 vitest tests; ADR 0005 |
| 5 | Task infra & DNS | Complete (merged, PR #14) | 404 backend + 311 frontend tests; live DNS run verified; ADR 0006 |
| 6 | Scope policy & port scanner | Complete (merged, PR #15) | 498 backend + 319 frontend tests; live lab scan verified; ADR 0007 |
| 7 | Header & TLS checker | Complete (merged, PR #16) | 570 backend tests; fixture servers + live lab verified; ADR 0008 |
| 8 | Threat intel | Not started (build 4th) | Stretch scope: two providers fully, third optional. Must accept the playbook's `indicators` reference (ADR 0009) |
| 9 | Network diagnostics | Not started (build 7th) | Stretch. Traceroute best-effort on Docker Desktop |
| 10 | Log analyzer | Not started (build 5th) | Stretch |
| 11 | File integrity monitor | Not started (build 6th) | Stretch. Demo on a named volume, not a Windows bind mount. Add `beat` to the prod profile |
| 12 | Playbook engine | Complete (merged, PR #19) | Built 1st of the remaining phases; 618 backend + 327 frontend tests; ADR 0009 |
| 13 | Reporting & export | Complete, CI green (PR #20, awaiting merge) | 691 backend + 335 frontend tests; live playbook PDF verified; ADR 0010 |
| 14 | Observability & polish | Not started (build 3rd) | Observability profile optional |

## Build order (approved 2026-10-02, ADR 0009)

Remaining phases: **12 → 13 → 14 → 8 → 10 → 11 → 9**. Core demo first, stretch after.
ADR 0009 has the dependency check and the checklist each deferred phase must follow.

## MVP cut line

**Core demo:** Phases 0–7, 12, 13 (DNS → ports → headers/TLS → playbook → PDF report).
**Stretch:** Phases 8–11. **Optional:** the observability parts of Phase 14.

## Kickoff decisions (2026-10-01)

React 19, Node 24, TypeScript 6.0, `redis:7.4-alpine`, Python 3.12 inside the
containers. See `docs/adr/0001-architecture-and-stack.md`.

## Open items carried forward

- Starlette warns that TestClient on `httpx` is deprecated in favour of `httpx2`. Runtime
  stays on httpx 0.28.1 (ADR 0008); revisit the TestClient dependency when Starlette drops it.
- After a frontend dependency change, refresh the `frontend_node_modules` volume:
  `docker compose exec frontend npm ci` (rebuilding the image alone does not).
- Password analyzer: the optional HIBP k-anonymity check (spec "optional future") is not
  implemented; it would be the only network call in the local tools.
- Existing dev installs: run `docker compose down` once so networks are recreated with the
  pinned subnets (ADR 0007).
- Re-check that nginx's `connect-src 'self'` allows same-origin `wss:` in all target
  browsers (Phase 14).
- Existing dev volumes need the test DB once:
  `docker compose exec postgres sh /docker-entrypoint-initdb.d/02-test-db.sh`.
- The access-log route template relies on a FastAPI 0.14x internal (ADR 0002). A test pins it.
- Dependabot ignores semver-major updates for Docker images and npm packages (TypeScript and
  @types/node majors are deliberate upgrades). PR #9 (TypeScript 7, @types/node 26) was closed
  for that reason.
- CI on `main` is green again (2026-10-02): the gitleaks failure since Phase 2 came from fake
  test credentials, now allowlisted as exact literals in `.gitleaks.toml`.
- LICENSE copyright holder (`Anshuman-Singh-14`) needs confirming by the repo owner.
- The repo lives in OneDrive. Moving it to a non-synced path is recommended.
- Reports have no retention policy yet (the app role cannot delete them by design). Decide
  on retention, and how it is applied, in Phase 14.
- Dev DB has leftover smoke-test admins (`p3smoke`, `p5smoke`, `e2ereports`). Disable them
  from another admin account before any shared demo.

## Phase 13 log

- **Design:** ADR 0010. One `ReportDocument` per report (a tool run or a playbook run,
  built from the same `load_detail` the run page uses), rendered by exporter plugins.
- **Exporters** (`app/reports/exporters/`, one `@register` class each, published by
  `GET /reports/formats`; the frontend builds its buttons from it):
  - **PDF (ReportLab):**
    - Cover page, then an executive summary with a severity chart and priorities.
    - Scope and method: tools and versions, parameters, playbook steps.
    - Findings table, then detailed findings (explanation, rationale, remediation,
      evidence, references).
    - Errors, a truncated raw-data appendix, and "Page X of Y" on every page.
    - Every dynamic string is escaped; raw data uses `Preformatted`; references are not linked.
  - **CSV:** one row per finding, formula-injection safe (`app/reports/csv_safe.py`).
  - **JSON:** the full document. **TXT:** a plain-text report.
- **Generation:** `sentinel.generate_report` on the default queue: compare-and-set claim,
  render in a thread under a 60 s timeout, a 20 MB cap, SHA-256 and size recorded,
  redelivery fails the report (`worker_lost`).
- **Migration 0006:** `reports` and `report_blobs`, SELECT/INSERT (+UPDATE on `reports`
  only), no DELETE.
- **API:**
  - `POST /reports` (analyst; source must be finished; 10/min and 3 in flight per user).
  - `GET /reports`, `GET /reports/{id}` and `GET /reports/{id}/download` (any role). Downloads
    are verified against the SHA-256 and audited, and fail closed.
  - `GET /admin/audit/export` (CSV/JSON, the viewer's filters, newest first, capped at
    10,000 rows with a truncation flag). Closes the item deferred from Phase 3.
- **Audit:** `report.exported` (request), `report.generated` (worker; success or failure),
  `report.downloaded`, and `audit.exported`.
- **Frontend:**
  - Export panel on finished run and playbook run pages: buttons per format for analysts;
    a report list for everyone that polls while reports generate, with download buttons.
  - `/reports` history page, linked from the sidebar.
  - CSV/JSON export on the audit page.
  - Downloads go through the API client (session refresh, timeout) and are saved from a blob.
  - Fixes: DataTable rows no longer swallow Enter on buttons inside them. Testing Library's
    async timeout is raised to 5 s, which stops random `findBy` timeouts under a full
    parallel run.
- **Docs:** ADR 0010, threat model T58–T63 (plus an accepted risk on PDF fonts), and the
  Phase 13 design note folded into the ADR.
- **Local acceptance (2026-10-04):**
  - Backend: 691 tests pass (unit + integration), with ruff, mypy and bandit clean, the
    migration round trip clean and `alembic check` reporting no drift.
  - Frontend: 335 tests pass on two consecutive full runs, with eslint, prettier and tsc
    clean and the production build OK.
  - CSV injection: payloads (`=HYPERLINK`, `+cmd`, `-2+3`, `@SUM`, tab/CR/LF prefixes,
    leading blanks, full-width `＝`) are neutralised in every field. End to end, a hostile
    banner from a real tool run and a hostile User-Agent in the real audit trail are both
    prefixed in the exported CSVs.
  - PDF: hostile `<a href="javascript:">`, `<img>` and `<font>` print as text, and the
    output has no `/Annot`, `/URI`, `/JavaScript` or `/Launch`.
  - Live, through the real worker: the Web Defensive Audit against `lab-https` (default
    `web_url`) →
    PDF (7 pages), CSV, JSON and TXT all COMPLETED; each download matched its SHA-256; the
    audit log shows 4 × `report.exported`, `report.generated` and `report.downloaded`, plus
    `audit.exported` for the admin CSV export.

## Phase 12 log

- **Order:** built first of the remaining phases. The approved reorder is recorded in ADR 0009,
  CLAUDE.md and the phases spec.
- **Definitions:**
  - YAML validated by Pydantic: typed inputs, defaults referencing earlier inputs, steps with
    `on_failure` and `optional`.
  - Load-time reference checks (backward-only, known inputs, unique ids).
  - Shipped: **Web Defensive Audit** (DNS → web port scan → header/TLS → threat intel, the
    last optional until Phase 8).
- **Safe references:** `{{ inputs.x }}` and `{{ steps.id.field[n] }}` over plain JSON only;
  no template engine, no attribute access, size-capped.
- **Orchestrator:** one Celery task runs the steps sequentially and in-process.
  - Each step is a normal `ToolRun` created through `RunService` (same checks and audit) and
    executed by `execute_run`, with the worker scope check on every step.
  - `on_failure` stop/continue, optional skip, reference errors, cancellation propagated into
    the running tool, redelivery handling, time limits summed from the steps.
- **Results:** unified, de-duplicated findings with provenance (`also_reported_by`), and a
  risk summary with headline and partial-coverage flag.
- **Live updates:** `playbook.update` events relayed over `/ws/playbooks/{id}`. The relay is
  shared with runs, and tickets now carry a kind.
- **Quotas:** playbooks count against the same per-user caps as manual runs; their steps are
  not counted twice.
- **Migration 0005:** `playbook_runs`, `playbook_steps`, `tool_runs.playbook_run_id`, with
  explicit grants (no DELETE).
- **Frontend:**
  - Playbooks page: steps with availability and active badges, a schema-generated input form
    behind the authorised-use gate, recent runs.
  - Run page: live step timeline with progress, cancel, step errors, links to tool runs,
    unified findings with the source step, risk summary.
- **Docs:** ADR 0009.
- **Local acceptance (2026-10-02):**
  - Backend: 618 tests pass, with ruff, mypy and bandit clean, `alembic check` reporting no
    drift and the migration round trip clean. Frontend: 327 tests pass with eslint, prettier
    and tsc clean.
  - Live against the lab:
    - The audit of `lab-https` streamed QUEUED → RUNNING 0/25/50/75% → COMPLETED.
    - DNS failed with a clear reason ("Enter a fully qualified domain name") and the audit
      continued; intel was skipped as not installed.
    - 11 unified findings, led by the HIGH self-signed certificate.
    - The cancel against a slow target ended CANCELLED, and `8.8.8.8` was refused at start
      (`out_of_scope`).

## Phase 7 log

- **SSRF guard:**
  - URL shape rules: http/https only, allowlisted ports, no credentials or control
    characters, at most 2048 characters.
  - Every hop is scope-checked and pinned to its IP, with Host and SNI preserved.
  - Manual redirects (at most 5) are re-validated, and a new host is re-scoped via the
    framework's `scope_check`. Denials are audited (stage `redirect`).
  - `trust_env=False`, plus caps on response bodies and headers.
- **Scope tightening:** domain rules no longer cover non-public addresses
  (`internal_via_domain`).
- **TLS:**
  - A verified handshake with the reason for any failure, then an unverified read of the
    certificate parsed with `cryptography` (new dependency).
  - RFC 6125 hostname matching and a TLS 1.0/1.1 acceptance probe.
- **Checks:**
  - HTTPS availability, the HTTP→HTTPS redirect, and certificate validity, chain, name,
    expiry, key and signature.
  - HSTS, CSP (with weakness analysis), clickjacking, nosniff, Referrer-Policy,
    Permissions-Policy and version disclosure.
  - Cookie flags. Cookie values are never stored.
- **Remediation:** knowledge YAML with ready-to-paste nginx and Apache snippets.
- **Framework:** `BaseTool.scope_host` (a URL tool scope-checks its host) and
  `ToolContext.scope_check`.
- **Lab:** `lab-https` (nginx with good headers, an HTTP→HTTPS redirect and a self-signed
  certificate).
- **Docs:** ADR 0008, threat model (T11 done; new T52–T54), and the httpx-vs-httpx2
  question settled.
- **Local acceptance (2026-10-02):**
  - Backend: 570 tests pass, with ruff, mypy and bandit clean.
  - Fixture servers on 127.0.0.1: the good HTTPS site has only INFO findings. The bad HTTP
    site produces the expected HIGH, MEDIUM and LOW findings. Expired, self-signed and
    wrong-host certificates are each HIGH, and SNI was verified on the pinned connection.
  - SSRF: redirects to the metadata IP, `file:`, `gopher:` and credential URLs are not
    followed, and loops stop at the limit. The live integration test audits the redirect
    denial.
  - Live lab:
    - `http://lab-https:8080/` → 301 → `https://lab-https:8443/`: TLS 1.3, self-signed
      (HIGH), all headers pass.
    - `http://lab-web:8080/`: no HTTPS (HIGH), CSP and clickjacking missing (MEDIUM),
      LOW findings for the remaining headers.
    - `example.com` (out of scope), `api` (hard-denied) and port 6379 were refused before
      any request.

## Phase 6 log

- **Scope policy:**
  - Pure decision logic with a hard infrastructure denylist (pinned compose subnets plus
    metadata, link-local and multicast ranges; IPv4-mapped addresses unwrapped).
  - Built-in allow list: loopback and the lab network. Admin CIDR and domain entries are
    validated (no broader than /8, no overlap with the denylist), and every change is
    audited as a security event.
  - Every resolved address must be in scope. The checked addresses are pinned and handed
    to the tool (anti-rebinding).
- **Authorisation:**
  - Versioned authorised-use statement; acceptance stored with hash and IP, insert-only,
    and audited.
  - Active runs require it. The API pre-checks scope; the worker checks authoritatively
    before any traffic.
- **Migration 0004:** `scope_entries` and `authorization_acknowledgements`, with explicit
  grants.
- **Port scanner:**
  - TCP connect scan with bounded concurrency, presets and a parsed custom list (capped).
  - Passive banners plus a HEAD probe on HTTP ports; sanitised banners.
  - Fingerprinting to CPE, and exposure findings by class.
  - NVD CVE enrichment: Redis cache, shared rate window, retries; CVSS-based severity with
    LOW/MEDIUM confidence and explicit rationale.
- **Lab profile:** lab-web (nginx), lab-redis (open Redis) and lab-banners (a fake-banner
  server; no real vulnerable software) on an internal `lab` network.
- **Frontend:** authorised-use gate and allowed-targets summary on active tools, an admin
  Scope policy page (rules, add, enable/disable, remove, read-only denylist), and
  re-gating when the server demands it.
- **Docs:** ADR 0007, threat model (T10, T44 and T45 done; new T46–T51), `.env.example`,
  and the CLAUDE.md lab command.
- **Local acceptance (2026-10-02):**
  - Backend: 498 tests pass (unit plus integration), with ruff, mypy and bandit clean and
    `alembic check` reporting no drift. Frontend: 319 tests pass with eslint, prettier and
    tsc clean.
  - Live, against the lab through the Vite proxy:
    - lab-banners: 21/22/23/25/3306 found; CVE-2011-2523 is CRITICAL at MEDIUM confidence;
      Exim and MySQL CVEs are at LOW (Ubuntu builds).
    - lab-web: nginx on 8080. lab-redis: exposed database (HIGH).
    - `8.8.8.8`, `postgres` (10.231.0.2) and `169.254.169.254` were denied with reasons.
    - The second run was served from the NVD cache.
  - Two bugs found live and fixed with regression tests: the vsftpd CPE vendor, and the
    limiter counting refused attempts.

## Phase 5 log

- **Run lifecycle:**
  - `tool_runs` and `findings` (migration 0003, explicit grants, no DELETE).
  - `RunService` covers create, list, get and cancel. The run row and its audit event
    commit before dispatch, and the task carries the run id only.
  - Compare-and-set status transitions.
  - Quotas: 20 runs per minute and 3 active runs per user.
  - Active tools are refused until Phase 6 (fail closed).
- **Worker:** the `sentinel.run_tool` task with one event loop per process. Claim, audit,
  execute, persist and audit. Progress via Redis pub/sub, cooperative cancel, three-layer
  time limits, `worker_lost` handling and a 1 MB raw-output cap.
- **Realtime:** `/ws/runs/{id}` relays updates, protected by an Origin check and single-use
  tickets (T12 done). Vite proxies `/ws`.
- **API:**
  - `POST /tools/{id}/runs`
  - `GET /runs` (filters, keyset paging)
  - `GET /runs/{id}` (ToolResult plus progress)
  - `POST /runs/{id}/cancel`
  - `POST /runs/{id}/ws-ticket`
- **DNS tool (`dns_lookup`):**
  - dnspython with explicit resolvers, and IDNA/RFC 1123 domain validation that refuses
    internal names.
  - Checks: SPF, DMARC, CAA, dangling CNAMEs, name server redundancy, private-IP exposure
    and NXDOMAIN, with knowledge YAML.
  - The worker joins an `egress` network.
- **Frontend:**
  - Run forms generated from each tool's JSON Schema, with server 422 errors shown per
    field.
  - `useRunStatus` (WebSocket with polling fallback).
  - Run page: timeline, progress, cancel, structured errors, and findings / raw /
    parameters tabs.
  - Run history page with URL-driven filters.
- **Docs:** ADR 0006 and threat-model rows T41–T45 (T12 done).
- **Local acceptance (2026-10-02):**
  - Backend: 404 tests pass (unit plus integration on real Postgres and Redis), with ruff,
    mypy and bandit clean and `alembic check` reporting no drift. Frontend: 311 tests pass
    with eslint, prettier and tsc clean.
  - Live against the dev stack through the Vite proxy:
    - The example.com run went QUEUED → RUNNING (5/55/75/95%) → COMPLETED over the
      WebSocket with 5 findings.
    - A reserved domain was rejected with a structured 422.
    - Cancelling mid-run ended CANCELLED, and a repeat cancel returned 409.
    - The run history lists the runs, and the audit chain verified OK with every run
      audited by api and worker.
    - Worker logs carry the originating `request_id`.

## Phase 4 log

- **Tools** (each one is pure logic, a unit test and a lazy-loaded component under
  `src/features/tools/local/`):
  - **Password analyzer:** charset entropy vs the zxcvbn estimate with an explanation of the
    gap, pattern explanations, crack-time ranges for three named scenarios, and
    recommendations.
  - **JWT inspector:** decode with clear errors, timeline, findings on the backend severity
    scale, and local Web Crypto verification for HS, RS, PS, ES and EdDSA. Algorithm
    confusion and private keys are refused.
  - **Hash tool:** SHA-256/384/512, plus SHA-1 and MD5 labelled legacy, for text and streamed
    files with progress and cancel. Constant-time checksum comparison.
  - **Encoder/decoder:** Base64, Base64URL, URL and hex with positioned errors, auto-detect
    suggestions, a round-trip check and an "encoding is not encryption" banner.
- **Shared:** a local-only badge pinned to the top of every tool, explainer panels, the
  encoding / hashing / encryption comparison table, and `LocalFinding`.
- **Isolation proof:**
  - A static import-graph test bans the API client, network, storage and console APIs. A
    mutation check confirmed it fails when a `fetch` is planted.
  - A runtime test drives every tool with all network APIs trapped and the browser marked
    offline.
- **Offline:** tool chunks and dictionaries are prefetched when the browser is idle, and
  `RequireAuth` keeps the cached user when a background refetch fails.
- **Dependencies:** `@zxcvbn-ts/core` 4.2.0, `@zxcvbn-ts/language-common` 4.1.3,
  `@zxcvbn-ts/language-en` 4.1.1, `@noble/hashes` 2.4.0. See ADR 0005 for why Web Crypto
  alone was not enough.
- **Docs:** ADR 0005 and threat-model rows T38–T40.
- **Local acceptance (2026-10-02):**
  - 289 vitest tests pass on the host and in the container; eslint, prettier and tsc are
    clean; `npm audit` reports 0 vulnerabilities.
  - The production build has no `eval` or `new Function`, the main bundle is unchanged
    (~412 kB), and the dictionaries are lazy chunks.
  - Vite transforms every new module.

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
