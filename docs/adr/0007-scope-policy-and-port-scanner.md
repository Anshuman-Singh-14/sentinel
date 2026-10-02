# ADR 0007 — Scope policy, authorised use and the port scanner

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 6

## Context

The port scanner is Sentinel's first **active** tool: it sends traffic to
other machines. Without strong controls a defensive tool becomes a pivot (scan
Sentinel's own database), a nuisance (scan third parties) or a liability
(scans nobody authorised). Phase 5 refused every active tool outright; this ADR
replaces that refusal with a real policy.

## Decisions

### 1. Three layers before a packet is sent

1. **Authorised-use acknowledgement.** Each user accepts a versioned
   statement once, before their first active run.
   - The acceptance is stored (INSERT/SELECT-only table, with the statement's
     SHA-256 and the source IP) and audited as
     `scope.authorization.acknowledged`.
   - Bumping `AUTHORIZATION_STATEMENT_VERSION` makes everyone accept the new
     wording.
   - The API refuses active runs without it (`authorization_required`).
2. **API pre-check.** For IP literals and names the API can resolve, a denial
   is immediate: 403 `scope_denied` with a reason, plus a
   `tool.run.denied_scope` security event (stage `api`). The API is not on
   the lab network, so it cannot resolve lab names; those runs are queued.
3. **Worker check (authoritative).** It runs right before the tool, with the
   worker's DNS view and the policy *as it is now*. A denial here fails the
   run with `scope_denied` and is audited (stage `worker`).

### 2. The decision procedure (`app/core/security/scope.py`)

- **Resolve first.** An IP literal resolves to itself.
- **Hard denylist first, unconditionally.** If *any* resolved address falls in
  one of these ranges, the target is denied:
  - Sentinel's own subnets (`SCOPE_INFRA_SUBNETS`).
  - `0.0.0.0/8`, `169.254.0.0/16` (incl. 169.254.169.254), multicast,
    `240.0.0.0/4`, Alibaba Cloud metadata, `::`, `fe80::/10`, `ff00::/8`
    and `fd00:ec2::254`.
  - IPv4-mapped IPv6 addresses (`::ffff:10.231.0.2`), which are unwrapped
    first so they cannot slip past the IPv4 rules.

  The denylist lives in code and settings, **never in the database**, so no
  admin entry (not even `0.0.0.0/0`) and no database write can lift it.
- **Allow** if the host name matches an allowed domain suffix (label-aware:
  `badexample.org` does not match `example.org`), or if **every** resolved
  address is inside an allowed CIDR. A name that resolves half inside and
  half outside the scope is ambiguous, so it is denied.
- **Then pin.** The checked addresses are handed to the tool in
  `ToolContext.authorized_addresses`. The scanner connects only to those and
  never re-resolves the name, so a DNS change between check and connect
  (rebinding) has no effect. The scanner also refuses to run without them.

### 3. Policy sources

- **Built-in allow** (`SCOPE_DEFAULT_ALLOW`): loopback plus the lab network.
  This is the spec's "localhost and the compose network".
- **Admin entries** (`scope_entries`): CIDRs or domain suffixes with a reason.
  They can be enabled, disabled or removed, and every change is a
  `scope.policy.changed` security event.
- **Validation of admin entries:**
  - CIDRs broader than /8 (IPv4) or /32 (IPv6) are refused.
  - Entries that overlap the hard denylist are refused.
  - Domains go through the same IDNA/RFC 1123 validator as the DNS tool.
- **Who sees what:** `GET /scope` shows any role what may be targeted. The
  hard denylist (internal addressing) is shown to admins only.

### 4. Pinned Docker subnets and the lab

- The compose networks are pinned so the denylist can name Sentinel's
  infrastructure by address: internal `10.231.0.0/24`, edge `.1.0/24`,
  egress `.2.0/24`, lab `.10.0/24`. The same values feed
  `SCOPE_INFRA_SUBNETS` and `SCOPE_DEFAULT_ALLOW` from one set of
  `SENTINEL_*_SUBNET` variables.
- **Consequence:** existing installs must run `docker compose down` once so
  the networks are recreated with the pinned subnets.
- The `lab` profile adds three targets on an internal (no-egress) network,
  reachable only from the worker:
  - **lab-web:** unprivileged nginx on 8080.
  - **lab-redis:** Redis without a password, the classic exposed database.
  - **lab-banners:** a ~60-line standard-library server that only *sends the
    greeting banners* of old vsftpd, OpenSSH, Exim, a telnetd and MySQL. No
    vulnerable software is shipped. It is non-root, has all capabilities
    dropped and a read-only filesystem, and binds low ports via the
    namespaced `ip_unprivileged_port_start` sysctl.

### 5. The scanner (`app/tools/port_scanner`)

- **Scanning:** a full TCP connect per port (`asyncio.open_connection`), with
  a semaphore (100 concurrent), a 1 s connect timeout and a 2 s banner
  timeout, progress about every 5%, and a cancel check before each connection.
  There are no SYN scans, raw sockets, OS fingerprinting or exploit checks,
  and the worker gets no extra capabilities.
- **Ports:** presets `top-100`, `top-1000` and `web` are Sentinel's curated
  lists, not Nmap frequency data. A custom list is parsed with a hard cap
  (`PORT_SCAN_MAX_PORTS`, default 1024) that is checked while expanding
  ranges.
- **Banners:**
  - Banners are read passively. The only probe is `HEAD / HTTP/1.0` on known
    clear-text HTTP ports, and TLS ports are not probed in plain text.
  - Non-printable bytes are escaped and banners are capped at 512
    characters.
  - Only the status line and `Server` header of an HTTP response are kept.
- **Exposure findings:** every open port gets a finding by exposure class
  (knowledge YAML citing CIS Controls and CWE):
  - CRITICAL: container APIs.
  - HIGH: clear-text admin, databases, remote desktop, file sharing.
  - MEDIUM: clear-text file transfer, directory services, message brokers.
  - LOW/INFO: SSH, web and mail.

### 6. CVE enrichment

- **Fingerprinting:** banners map to a product, version and one or more CPE
  vendor:product candidates. For example, vsftpd is filed in the NVD as
  `vsftpd_project:vsftpd`, and nginx under both `f5:nginx` and `nginx:nginx`.
- **NVD query:** CVE API 2.0 with `virtualMatchString`, which matches version
  ranges.
  - Results are sorted by CVSS and capped at 10 per product; up to 5 become
    findings.
  - Severity comes from the CVSS v3.1 bands via `severity.py`. CVSS v2-only
    CVEs are mapped onto the same bands and say so.
- **Confidence is never HIGH:**
  - **MEDIUM:** a clean upstream version string.
  - **LOW:** a distribution package marker (Ubuntu, Debian, `.el7` and
    similar), because distributions backport fixes without changing the
    version.
  - Each rationale explains why.
- **Cache:** every answer, including "no CVEs", is cached in Redis as JSON for
  24 h.
- **Rate limit:**
  - A Redis fixed window shared by all workers, at 4 or 49 requests per 30 s
    (one below the NVD's limits, because a fixed window is not rolling).
  - Refused attempts are handed back. The first live run showed that counting
    them starved the next window.
  - HTTP 403, 429 and 503 are retried twice, honouring Retry-After.
- **Failure:** the scan still completes, with a `cve_lookup_unavailable`
  error. A "no CVEs found" finding is only emitted when the lookup actually
  ran.
- **Dependency:** `httpx` moves from dev to runtime. Later phases need it
  too; the Starlette deprecation concerns only `TestClient`.

### 7. Quotas

Added 200 runs per user per hour, on top of the Phase 5 limits (20 per minute
and 3 concurrent).

## Consequences

- **Lab acceptance, verified live:**
  - lab-banners: ports 21, 22, 23, 25 and 3306 with products identified;
    CVE-2011-2523 (the vsftpd backdoor) is CRITICAL at MEDIUM confidence,
    Exim and MySQL CVEs are at LOW (Ubuntu builds), and OpenSSH 7.4 CVEs are
    at MEDIUM.
  - lab-web: nginx on 8080.
  - lab-redis: exposed database (HIGH).
  - `8.8.8.8`, `postgres` and `169.254.169.254` are denied with reasons and
    audited.
- **Integration tests** cover:
  - the acknowledgement flow and its grants;
  - API- and worker-stage denials;
  - infra hard denial (`postgres` really resolves to the pinned internal
    subnet in the test container);
  - admin CRUD and its audit trail;
  - rejected dangerous entries;
  - policy changes taking effect immediately;
  - a real scan of a local socket server through the worker;
  - the limiter regression.
- **Operator duty:** every admin scope entry needs written authority for what
  it covers. The policy is a technical control, not a legal one.
