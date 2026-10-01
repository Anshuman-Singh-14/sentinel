# 02 — Modules & Features

Each tool is its own package (see `01-architecture.md`). Every backend tool returns `ToolResult` and produces educational findings.

---

## Category 1 — Client-side utilities (browser only)

Shared rules: no network calls with user input, no analytics on input, no persistence (no localStorage of inputs). A persistent "Runs locally — nothing leaves your browser" badge is shown on each tool. A unit test asserts that these components never call the API client. Use the Web Crypto API (`crypto.subtle`) rather than third-party crypto libraries where possible.

### 1. Password Strength & Entropy Analyzer
- Length, character-class diversity, charset-based entropy estimate **and** a pattern-aware estimate (zxcvbn-ts, bundled locally) with an explanation of why they differ
- Repetition, sequences (`abc`, `123`), keyboard walks, dates, leetspeak substitutions, common-password dictionary (bundled locally)
- Estimated crack-time ranges for online-throttled vs offline-fast-hash scenarios, with assumptions shown
- Actionable recommendations; explain passphrases and password managers
- Optional future: k-anonymity breach check (HIBP range API) as an explicit opt-in that sends only a 5-char SHA-1 prefix. Off by default and clearly labelled

### 2. JWT Inspector
- Decode header and payload locally (base64url), pretty-print claims, human-readable `exp`, `iat`, `nbf` with relative time
- Flag: `alg: none`, symmetric vs asymmetric algorithm, missing `exp`, very long lifetimes, expired/not-yet-valid tokens, sensitive-looking data in the payload, `kid`/`jku`/`x5u` header presence with explanation
- Prominent note: **decoding is not verifying**. Optional local signature verification when the user pastes a secret or public key (Web Crypto), still fully client-side

### 3. Hash Generator & Verifier
- SHA-256 and SHA-512 (optionally SHA-384, and SHA-1/MD5 labelled "legacy — not collision resistant")
- Hash text and local files (streamed in chunks via `File.stream()` with progress for large files)
- Compare against an expected hash using constant-time comparison; normalize case/whitespace
- Explainer: hashing vs encryption vs encoding; why passwords need slow hashes (bcrypt/argon2), not SHA-256

### 4. Multi-Format Encoder / Decoder
- Base64, Base64URL, URL encoding, Hex
- Auto-detect suggestion, round-trip check, clear error messages for invalid input
- A comparison panel: Encoding vs Hashing vs Encryption (reversible? needs key? purpose?)
- Explicit banner: **encoding is not encryption**

---

## Category 2 — Backend asynchronous tools

### 1. Port Scanner & Banner Grabber (`port_scanner`, active)
- `asyncio.open_connection` TCP connect scanning; `asyncio.Semaphore` for bounded concurrency
- Input: single host (IP or hostname) plus ports as list/ranges/presets (`top-100`, `top-1000`, `web`); hard cap on port count per run from settings
- Per-connection timeout, overall hard time limit, cooperative cancellation, progress every N ports
- Service identification from a local port→service map, then refined from banners (passive read, and a safe protocol-appropriate probe such as `HEAD / HTTP/1.0` on web ports only)
- Banner length cap, non-printable bytes escaped
- **CVE enrichment:** parse product/version from banners into a candidate CPE, query the NVD CVE API 2.0 with caching in Postgres/Redis and rate-limit handling (optional NVD API key via env). Banner matches are labelled `confidence: LOW/MEDIUM` with an explanation that banners can be spoofed or incomplete
- Findings: open ports with exposure explanation (e.g. Telnet/FTP cleartext, exposed database ports), potential CVEs with CVSS-based severity
- No SYN/stealth scans, no OS fingerprinting evasion, no exploit checks

### 2. DNS & Domain Intelligence (`dns_lookup`, passive)
- `dns.asyncresolver` with configured timeout and lifetime
- Records: A, AAAA, MX, TXT, NS, CNAME, plus SOA and CAA
- Forward resolution, reverse DNS (PTR) for resolved IPs
- Security findings from records: SPF present/permissive (`+all`), DMARC present and policy strength (`_dmarc` TXT), CAA absent, dangling CNAME hints, single NS provider
- Structured output usable as input to later playbook steps (resolved IPs)

### 3. Threat Intelligence Integrator (`threat_intel`, passive)
- Provider pattern: `providers/base.py` with `AbuseIPDBProvider`, `VirusTotalProvider`, `ShodanProvider`. Each enabled only if its API key env var is set; `GET /api/v1/tools` reports which are available
- Run providers concurrently with per-provider timeout; one provider failing does not fail the run (partial results + `errors[]`)
- Respect rate limits (429 handling, exponential backoff with jitter, per-provider token bucket in Redis), cache results with TTL
- Normalize to a common reputation model (score, categories, last reported, source) with source attribution on every finding
- Never log API keys or full provider responses containing keys

### 4. HTTP Security Header & TLS Checker (`header_tls`, active)
- `httpx.AsyncClient` with timeouts, redirect limit (≤5), response size cap, and the **SSRF guard** from `04-security.md` applied to the initial URL and every redirect
- Headers: HSTS (presence, max-age, includeSubDomains, preload), CSP (presence plus basic weakness checks like `unsafe-inline`, `*`), X-Frame-Options / CSP `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, plus informational disclosure headers (`Server`, `X-Powered-By`)
- Cookies: `Secure`, `HttpOnly`, `SameSite` flags
- TLS via `ssl` + `asyncio`: HTTPS availability, HTTP→HTTPS redirect, negotiated protocol version, certificate validity, chain verification result, days to expiry, issuer, subject, SANs, hostname match
- Remediation includes example config snippets for nginx and Apache. Defensive recommendations only

### 5. Log File Analyzer (`log_analyzer`, local)
- Input: upload (size-capped, streamed) **or** a file within the configured read-only `LOG_ROOT` mount (path guard applies)
- Parser plugins: `auth_log` (OpenSSH), `nginx_access` (combined format). Each parser declares its format and regex; unrecognized lines are counted, not fatal
- Detection rules as configurable data (YAML): failed SSH login bursts (N in T window per IP), invalid-user enumeration, successful login after failures, root login attempts, path traversal patterns (`../`, encoded variants), common scanner user agents, high request rate per IP, 4xx/5xx spikes
- Output per detection: first/last timestamp, source IP, event type, count, severity with rationale, explanation, remediation (fail2ban, key-only auth, rate limiting, WAF rules)
- Processes line-by-line (streaming); never loads huge files fully into memory

### 6. File Integrity Monitor (`fim`, local)
- Paths restricted to `FIM_ROOTS` allowlist (mounted read-only into the worker); path guard applies; symlinks not followed outside roots
- Baseline: SHA-256 per file plus size, mtime, mode, owner uid/gid; stored in `fim_baselines` / `fim_baseline_entries`; baseline records who created it and when
- Compare: MODIFIED, ADDED, REMOVED, METADATA_CHANGED (permissions/owner) with severity based on path sensitivity (configurable patterns, e.g. `/etc/`, `*.conf`, binaries)
- Chunked hashing, file count and size limits, exclude patterns, progress reporting
- Optional scheduled checks via Celery beat (later in the phase)

### 7. Network Diagnostics (`net_diag`, active)
- `icmplib` async ping (count, interval, timeout) → RTT min/avg/max, jitter, packet loss with plain-language interpretation
- Traceroute via `icmplib.traceroute` where privileges allow
- Container note: unprivileged ICMP requires `net.ipv4.ping_group_range` sysctl on the worker; traceroute needs `NET_RAW`. Grant it **only** to the worker container and document the trade-off. If unavailable, return a structured "unsupported in this environment" result
- Optional TCP "ping" (connect time to a port) as a fallback

---

## Security Playbook Engine

- Playbook definitions in YAML/JSON under `playbooks/definitions/`, validated by a Pydantic schema: ordered steps, each with `tool_id`, params (may reference outputs of earlier steps, e.g. `{{ steps.dns.resolved_ips[0] }}` via a small safe resolver — **no** Jinja eval of arbitrary expressions), `on_failure: stop | continue`
- Execution via a Celery chain/orchestrator task; each step creates a normal `ToolRun` linked to the `PlaybookRun`
- Progress reporting per step and overall; cancellation propagates
- Result aggregation: merged, de-duplicated findings sorted by severity, per-step status, overall risk summary
- Initial built-in playbook — **Web Defensive Audit**: DNS → Port Scan (web preset) → Header & TLS → Threat Intel (resolved IPs) → Unified Findings → Report
- Keep v1 sequential and simple; design so parallel steps can be added later

---

## Reporting & Export

- Export any `ToolRun` or `PlaybookRun` as PDF, JSON, CSV, Plain Text via exporter plugins (`reports/exporters/`)
- PDF (ReportLab): cover page, scope/target, who ran it and when, tool versions, executive summary with severity chart, findings table, detailed findings with explanation/remediation/references, appendix of raw data (truncated)
- CSV: one row per finding, formula-injection safe (prefix cells starting with `= + - @`)
- Report generation runs as a Celery task; report metadata stored in `reports`; exports are audited
