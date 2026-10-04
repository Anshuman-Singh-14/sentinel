# ADR 0012 — Threat intelligence integrator

- **Status:** Accepted
- **Date:** 2026-10-04
- **Phase:** 8 (built after 12–14, as approved in ADR 0009)

## Context

02-modules.md, tool 3:
- providers for AbuseIPDB, VirusTotal and Shodan, each enabled only when its
  API key is set, with `GET /api/v1/tools` reporting which are available;
- concurrent lookups with a timeout per provider, and partial results when one
  provider fails;
- 429 handling with exponential backoff and jitter, a per-provider budget in
  Redis, and a result cache with a TTL;
- a common reputation model with source attribution on every finding;
- API keys never logged.

Acceptance (05-phases.md): providers mocked in tests, missing keys disable
providers gracefully, and 429 handling tested.

ADR 0009's checklist for Phase 8: the Web Defensive Audit's
`indicators: "{{ steps.dns.resolved_ips }}"` reference must work, and the
exporters must render the new findings.

## Decisions

### 1. A generic "available" hook in the tool framework

A tool can be installed but unusable: threat intel without any API key.
`BaseTool.availability()` returns `ToolAvailability(available, reason,
details)`. The default is "always available", so other tools are unchanged.
The framework uses it in four places:

- **Catalogue:** `GET /tools` adds `available`, `unavailable_reason` and
  `status` (here `{providers: [{id, name, configured, env_var, supports}]}`).
  The status never contains a key.
- **Runs:** `POST /tools/{id}/runs` answers 409 with the reason instead of
  queuing a run that would fail.
- **Playbooks:** a step whose tool is unavailable is treated like a missing
  tool. An optional step is SKIPPED (`tool_unavailable`, with the reason); a
  required one makes the playbook unavailable.
- **Frontend:**
  - The tool page shows the reason and the provider list instead of the form.
  - The sidebar tags the tool "setup".
  - The playbook catalogue shows "not configured: skipped" and the reason.

This adds a hook to core code, not a per-tool special case (CLAUDE.md rule 9):
any future tool that needs configuration (log sources, FIM roots) uses the
same hook.

### 2. Indicators and privacy

- **Kinds:** IPv4/IPv6 addresses, domains, and MD5/SHA-1/SHA-256 hashes.
  At most 20 per run, de-duplicated.
- **Input format:** the API and playbooks pass a list. The generated form
  sends one string, split on commas, spaces or newlines. The JSON schema
  advertises a string so the existing form renders it.
- **Private addresses are never sent to a provider.** That covers anything
  that is not `is_global`: RFC 1918, loopback, link-local, documentation
  ranges, and IPv4-mapped forms of these. They appear as an INFO finding
  ("not looked up, by design"). A lookup would return nothing useful and would
  disclose internal network layout to a third party.
- **Domains** use the DNS tool's validator, which rejects `.internal`,
  `.local` and the other reserved suffixes.
- **Disclosure notice:** the tool description says plainly that indicators
  are sent to the configured services.
- **No scope check:** the tool is passive. It sends nothing to the
  indicators themselves, only to fixed provider endpoints. It runs on the
  existing `intel` queue.

### 3. Providers

| Provider | Kinds | Auth | Score | Verdict |
|---|---|---|---|---|
| AbuseIPDB `/check` | IP | `Key` header | abuse confidence 0–100 | ≥75 malicious, ≥1 suspicious, 0 harmless |
| VirusTotal v3 | IP, domain, hash | `x-apikey` header | % of vendors saying malicious | ≥3 vendors malicious, any malicious/suspicious → suspicious |
| Shodan `/shodan/host` | IP | `key` query parameter | not scored | UNKNOWN: exposure data (ports, CVEs), not reputation |

- **Normalised model:** each provider's answer becomes a `Reputation`
  (verdict, score, categories, last seen, link, and a small whitelisted
  `details` dict).
- **What is stored:** the full provider response is never stored or logged.
- **What 404 means:** "never seen", which is a result, not an error.

### 4. Severity criteria

The criteria are documented in `knowledge/threat_intel.yaml` and quoted in
each finding's rationale.

- **AbuseIPDB score:** ≥75 HIGH, 25–74 MEDIUM, 1–24 LOW, 0 INFO.
  - Confidence comes from the number of distinct reporters: ≥5 HIGH, ≥2
    MEDIUM, otherwise LOW.
- **VirusTotal malicious vendors:** ≥3 HIGH, 1–2 MEDIUM; suspicious only LOW;
  none INFO.
  - Confidence: ≥5 malicious vendors HIGH, ≥3 MEDIUM, otherwise LOW.
- **Shodan:** listed CVEs give MEDIUM with LOW confidence (banner-based, the
  same caveat as Sentinel's own scanner). Open ports only give INFO.
- **"Clean" results** have MEDIUM confidence: no reports is not proof of safety.
- **Attribution and remediation:** every finding names its source in the
  title and in `evidence.source`, and links to the provider's own page.
  Remediation covers both cases: "if this is yours (possible compromise)" and
  "if it is someone else's (block and search your logs)".

### 5. Robustness

`ProviderHttp` is shared by all providers. It provides:
- a per-provider request budget per minute, in a Redis window shared by all
  workers (`RedisWindowLimiter`, moved from the port scanner to
  `app/core/external.py`);
- 429 and 503 retried up to 3 attempts, honouring `Retry-After` (capped at
  10 s), otherwise exponential backoff with full jitter (capped at 8 s);
- a local budget that is exhausted fails fast with `rate_limited`, without
  calling the provider;
- a 1 MB response cap, no redirects, `trust_env=False`;
- user-safe errors that never include `str(exc)`. httpx exception text can
  contain the URL, and Shodan's key travels in the query string.

The defaults stay inside the free tiers: AbuseIPDB 30/min, VirusTotal 4/min,
Shodan 30/min, each overridable.

How lookups run (`service.investigate`):
- up to 4 lookups at once, each under a 10 s timeout;
- every result, including "not found", is cached for 6 h; errors are not
  cached.

How failures surface:
- One failing provider adds one run error ("VirusTotal: … (2 lookups without
  an answer)"), and the run completes with partial results.
- If every lookup fails, the run is FAILED rather than an empty "all clear".

### 6. Testing without respx

The spec suggests respx. httpx ships `MockTransport`, which does the same job
for this code, so no new dependency was added. The tool exposes a class-level
`http_transport` test seam, used by the integration tests to run the real
worker path against mocked providers.

## Consequences

- New settings and env vars: `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
  `SHODAN_API_KEY` (SecretStr), plus base URLs, budgets, timeout and cache
  TTL. Compose passes only the keys.
- Daily quotas (AbuseIPDB 1,000/day, VirusTotal 500/day on free tiers) are not
  tracked; the per-minute budgets and the cache keep normal use well below
  them.
- In the shipped Web Defensive Audit, when the DNS step fails (as it does
  for lab names), the intel step's reference cannot resolve, so it fails with
  `reference_error` and the playbook continues. Against a public domain it
  receives the resolved IPs.
- Threat model rows T70–T74.
