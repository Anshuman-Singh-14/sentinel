# ADR 0008 — HTTP header & TLS checker and the SSRF guard

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 7

## Context

The header/TLS checker fetches URLs the user supplies. This is the textbook
setting for server-side request forgery (SSRF): "check this URL" becomes
"fetch `http://169.254.169.254/` or `http://postgres:5432/` from inside
Sentinel". Redirects make it worse, because a harmless first URL can bounce
the server somewhere else. DNS rebinding lets a name resolve to a safe
address when it is checked and an internal one when it is fetched.

## Decisions

### 1. The SSRF guard (`app/core/security/ssrf.py` plus the scope policy)

1. **URL shape:**
   - `http`/`https` only; `file:`, `gopher:`, `dict:`, `ftp:` and
     `javascript:` are refused.
   - No credentials in the URL.
   - No spaces or control characters (header injection).
   - At most 2048 characters.
   - A valid host, and a port from `WEB_CHECK_ALLOWED_PORTS` (default
     80/443/8000/8008/8080/8443/8888, which keeps Redis/SSH/DB ports out
     even for in-scope hosts).
2. **Address check:** the checker is an *active* tool, so the full scope
   policy applies (ADR 0007). The hard denylist always applies (metadata,
   link-local, Sentinel's subnets, …), and the target must be explicitly in
   scope.
   - **Tightened this phase:** a domain-suffix rule now vouches only for
     *public* addresses. If an allowed name resolves to a private, loopback
     or otherwise non-global address, that address must also be covered by a
     CIDR rule. Otherwise whoever controls the domain's DNS could point it at
     `10.0.0.5` and reach internal hosts (`internal_via_domain`).
3. **Pinning:** the request goes to the checked IP literal, with the original
   name in `Host` and in TLS SNI. The certificate is verified against that
   name.
   - This was prototyped first, as PROGRESS.md asked: httpcore's
     `sni_hostname` extension sets the TLS `server_hostname`, the server saw
     SNI `localhost` while the socket went to `127.0.0.1`, and a wrong SNI
     failed with "Hostname mismatch".
   - Pinning therefore does not weaken certificate validation.
4. **Redirects:** `follow_redirects=False`, followed manually up to
   `WEB_CHECK_MAX_REDIRECTS` (5). Each `Location` is resolved (absolute,
   relative or protocol-relative) and re-validated by step 1.
   - **Same host:** the pinned addresses are reused, with no new DNS lookup.
   - **New host:** it goes through `ctx.scope_check`, a framework callback
     that re-runs the authoritative scope decision in the worker and audits
     any denial as `tool.run.denied_scope` (stage `redirect`).
   - **Refused hops:** a refused redirect is *reported* as a finding, not
     followed. The run still completes with what was allowed.
5. **Client hardening:**
   - `trust_env=False`, so `HTTP(S)_PROXY` variables cannot reroute requests.
   - No keep-alive pool reuse; per-request timeouts.
   - The body is read only up to `WEB_CHECK_MAX_BODY_BYTES` (256 KB);
     response headers are capped in number (100) and length (1 KB each).

### 2. Cookies are inspected, never stored

`Set-Cookie` headers are parsed on receipt into **name and attributes only**
(Secure, HttpOnly, SameSite, Path, Domain, persistent). The value is dropped
immediately and the raw `Set-Cookie` headers are removed from the stored
response. A session cookie is a credential, and storing it would make
Sentinel's database a source of live sessions. A test asserts that a fixture
cookie value never appears in the raw output or the findings.

### 3. TLS inspection (`ssl` plus `cryptography`)

- **Handshake 1, verified:** system trust store and hostname check, minimum
  TLS 1.2. If it fails, the `ssl` error gives the reason: OpenSSL verify
  codes are mapped to `expired`, `not_yet_valid`, `self_signed`,
  `unknown_issuer` and `hostname_mismatch`.
- **Handshake 2, unverified:** run only when handshake 1 fails, to read the
  certificate anyway. The stdlib returns no parsed details for an
  unverifiable certificate, so the DER is parsed with **`cryptography`**:
  - fields: subject, issuer, SANs, validity, serial, key type and size,
    signature hash;
  - checks: RFC 6125 hostname matching (one left-most wildcard label, SANs
    before CN).

  `cryptography` is the new dependency of this phase. It is also how the
  tests mint fixture certificates, so no keys or certificates are committed.
- **Handshake 3, legacy probe:** offers TLS 1.0/1.1 only. Acceptance is
  MEDIUM (RFC 8996). If the local OpenSSL cannot offer those versions at all,
  the result is "not tested", never a guess.
- **Headers on a failing certificate:** if certificate verification fails on
  the HTTP request too, the headers are fetched again without verification so
  they can still be assessed. The hop is marked `tls_unverified`, and the TLS
  findings carry the certificate problem.

### 4. Checks and remediation

- **Transport:**
  - HTTPS unavailable: HIGH.
  - HTTP not redirecting to HTTPS: MEDIUM. This is probed on port 80 only for
    default-port HTTPS targets, or observed when the user starts from an
    `http://` URL.
- **TLS:**
  - HIGH: expired, not yet valid, self-signed, untrusted chain, hostname
    mismatch.
  - MEDIUM: legacy protocols accepted, a weak key, a SHA-1 signature.
  - Expiring soon: LOW under 30 days, MEDIUM under 14.
- **Headers:**
  - HSTS: missing MEDIUM; weak (under 180 days or no includeSubDomains) LOW.
    HTTPS only, because browsers ignore HSTS over HTTP.
  - CSP: missing MEDIUM; report-only LOW.
  - CSP weaknesses: `'unsafe-inline'` without a nonce or hash, `'unsafe-eval'`,
    wildcard or whole-scheme script sources, unrestricted `object-src` (MEDIUM).
  - Clickjacking (no X-Frame-Options or `frame-ancestors`): MEDIUM.
  - LOW: `nosniff` missing, Referrer-Policy missing or `unsafe-url`,
    Permissions-Policy missing, version disclosure (`Server` with a version,
    `X-Powered-By`, …).
- **Cookies:**
  - Secure missing on an HTTPS site: MEDIUM.
  - HttpOnly missing: LOW, raised to MEDIUM when the name looks like a
    session cookie.
  - SameSite missing: LOW.
  - `SameSite=None` without Secure: MEDIUM.
- **Remediation snippets:** each remediation carries ready-to-paste **nginx
  and Apache** snippets in `engine/knowledge/header_tls.yaml`. `$$` escapes
  nginx variables in the templating.

### 5. Open question settled: httpx stays

`httpx` 0.28.1 is the runtime client. The Starlette notice recommending
`httpx2` concerns only `TestClient`; it is tracked separately and does not
affect runtime code.

## Consequences

- **Fixture tests** run real HTTP/HTTPS servers on `127.0.0.1` with
  certificates minted per session: valid via a test CA, expired, self-signed,
  and issued for another host. They cover:
  - good and bad header sets;
  - HTTP→HTTPS redirects on the same pinned host;
  - redirects into `169.254.169.254` (blocked by scope);
  - redirects to `file:`, `gopher:` and credential URLs (blocked by shape);
  - redirect loops;
  - unreachable hosts;
  - the cookie-value guarantee.
- **The lab** gains `lab-https`: nginx with good headers, an HTTP→HTTPS
  redirect and a self-signed certificate. Live, it yields a HIGH self-signed
  finding with all headers passing, while `lab-web` yields no-HTTPS (HIGH)
  plus the missing-header findings.
