# 04 — Security Hardening

Security is built in from Phase 0, not bolted on. Maintain `docs/threat-model.md` (STRIDE-style, updated each phase).

## 1. Zero shell execution
Forbidden: `subprocess`, `os.system`, `os.popen`, `shell=True`, `eval`, `exec`, `pickle.loads` on untrusted data, `yaml.load` without `SafeLoader`. Enforced by `bandit` in CI and a custom ruff/grep check that fails the build.

## 2. Scope & authorization controls (active tools)
Sentinel's active tools can send traffic to third-party systems, so misuse prevention is a core requirement:
- `ScopePolicy` configured by admins: allowed CIDRs and domain suffixes (e.g. lab ranges, `scanme.nmap.org`, owned domains). Default policy: only `localhost`, the compose network and explicitly listed targets
- Every active run checks the resolved IP(s) against the policy **after** DNS resolution; denials return a clear structured error and create a `tool.run.denied_scope` security event
- Before first active run, the user acknowledges an authorization statement ("I own or have written permission to test this target"); acknowledgement stored and audited
- Per-user quotas: concurrent runs, runs per hour, max ports per scan

## 3. SSRF guard (header/TLS checker, threat intel callbacks, any outbound URL fetch)
- Allow only `http`/`https`, standard or explicitly allowed ports
- Resolve hostname, reject private, loopback, link-local, multicast, reserved and cloud metadata ranges (`169.254.169.254`, `fd00:ec2::254`) unless the scope policy explicitly allows them
- Connect to the validated IP (pin resolution) to defeat DNS rebinding; send the original Host header / SNI
- Re-validate on every redirect; cap redirects, response size and total time

## 4. Input validation
Pydantic v2 models with strict types for all payloads:
- Domains: IDNA-normalized, RFC 1123 label rules, max 253 chars
- IPs/CIDRs: `ipaddress` module (not regex)
- Ports: 1–65535; ranges validated and expanded with a hard cap
- URLs: parsed with `httpx.URL`/`urllib.parse`, scheme allowlist
- Playbook params: validated against each step's `params_model`
- Reject unknown fields (`extra="forbid"`)

## 5. Path traversal protection
Central `PathGuard.resolve(user_path, allowed_roots)`:
- Reject null bytes; `Path(root, user_path).resolve(strict=True)`; require `resolved.is_relative_to(root)` for one of the allowed roots
- Do not follow symlinks that leave the roots; re-check at open time (`os.open` with `O_NOFOLLOW` where suitable) to reduce TOCTOU risk
- Allowed roots come from env and are mounted read-only into the worker
- Uploads: stored under a random name in a temp dir, size-capped, content never executed, deleted after processing

## 6. Secrets management
- `pydantic-settings` with `SecretStr` for keys and passwords; `.env.example` documents every variable; `.env` gitignored
- Compose uses `env_file`; document Docker secrets as the production option
- `detect-secrets` or `gitleaks` in pre-commit
- Secrets never returned by any API; provider status shows only "configured: true/false"

## 7. Rate limiting & timeouts
- slowapi limits per user and per IP; stricter limits on `/auth/login` and run-creation endpoints
- Timeouts: socket connect/read, DNS lifetime, HTTP (connect/read/total), external API calls, DB statement timeout
- Celery: `task_soft_time_limit`, `task_time_limit`, `acks_late`, `worker_prefetch_multiplier=1`, result expiry, per-queue concurrency
- External APIs: token buckets, 429/Retry-After handling, exponential backoff with jitter, circuit breaker after repeated failures

## 8. Error handling
- Custom exception hierarchy (`ValidationError`, `ScopeDenied`, `ToolTimeout`, `ProviderError`, `PathDenied`…) mapped to structured JSON errors with `request_id`
- Global handler returns generic 500 messages; details only in server logs
- Tools convert failures into `status: FAILED` results with `errors[]`; partial results preserved

## 9. Web application security
- Security headers on the API and frontend (Sentinel should pass its own header checker): CSP, HSTS (prod), X-Content-Type-Options, frame-ancestors 'none', Referrer-Policy
- Strict CORS allowlist from env
- React: never `dangerouslySetInnerHTML` with tool output; render raw data as escaped text/JSON viewer
- CSV exports formula-injection safe; PDF generation never renders untrusted HTML

## 10. Container & supply chain
- Non-root users, minimal base images (`python:3.12-slim`, `node:20-alpine` → `nginx:alpine`), multi-stage builds
- Read-only root filesystems where possible, `no-new-privileges`, drop all capabilities (add `NET_RAW` to worker only if traceroute is enabled)
- Postgres/Redis not exposed to host; Redis `requirepass`
- Pinned dependencies with lockfiles; `pip-audit` and `npm audit` in CI; Dependabot config

## 11. Security test suite (`tests/security/`)
SSRF (private IPs, metadata IP, redirect to internal, DNS rebinding simulation), path traversal (`../`, encoded, symlink escape, null byte), scope bypass attempts, authz (viewer cannot run tools, analyst cannot view audit), redaction, rate limiting, CSV injection, and a static test that forbidden functions are absent from the codebase.
