# ADR 0005 — Client-side utilities

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 4

## Context

Four tools handle the most sensitive input in Sentinel: passwords, bearer
tokens, signing secrets and arbitrary files. CLAUDE.md rule 2 says this input
must never reach the backend, never be logged and never be stored. That has to
be **demonstrable**, not just intended. The tools also have to keep working
offline.

## Decisions

### 1. Structure

Each tool is a folder under `frontend/src/features/tools/local/`:

- a pure logic module with no React and no I/O (`codec.ts`, `hashing.ts`,
  `jwt.ts`, `analysis.ts`);
- a unit test for that logic;
- a default-exported component.

The shared building blocks live in `shared/`:

- byte conversions;
- a `LocalFinding` type that mirrors the backend `Finding`, so the local tools
  speak the same Educational Translation Engine language;
- layout pieces: the badge, explainers and the comparison table.

Routes are generated from the manifest in `registry.ts` using React Router's
route-level `lazy`, so every tool is its own chunk.

### 2. Proving isolation

There are two complementary tests:

- **Static** (`isolation.static.test.ts`):
  - It walks the import graph from every tool entry module and fails if any
    reachable project file is `src/lib/api`, or mentions `fetch`,
    `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, browser
    storage, `document.cookie`, `console.*`, image beacons, `window.open`,
    TanStack Query or a hard-coded URL.
  - Third-party imports are limited to an allowlist of pure-computation
    packages.
  - A mutation check (planting a `fetch(` in a reachable module) made the test
    fail as expected.
- **Runtime** (`isolation.test.tsx`):
  - `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` and
    `Storage.setItem` are replaced by traps that record the call and then
    throw, and `navigator.onLine` is set to false.
  - Each tool is driven through its main flow: encode, hash text and a file,
    decode and verify a JWT, analyse a password.
  - Every tool must still produce its result, and no trap may fire. This test
    covers both "no network calls" and "works offline".

Inputs also set `autocomplete="off"`, `spellcheck=false` and
`autocorrect="off"`. Some browser spell-checkers send text to a cloud service.
The password field also asks password managers not to save it.

### 3. Offline behaviour

- After the shell mounts, an idle callback prefetches every local tool chunk
  and the zxcvbn dictionaries. A user who loses connectivity later can still
  open any tool.
- `RequireAuth` now keeps the last known user when a background refetch fails.
  Before this change, a dropped connection replaced the whole app with the
  outage card, which would have locked users out of tools that need no server.
- The tools stay behind login, like the rest of Sentinel. Making them public
  would add an unauthenticated surface for little gain.

### 4. Libraries

| Package | Why |
|---|---|
| `@zxcvbn-ts/core` 4.2.0, `language-common` 4.1.3, `language-en` 4.1.1 | Named in the spec: the pattern-aware estimate with bundled dictionaries (leaked passwords, common words, names, keyboard graphs). It covers repeats, sequences, keyboard walks, dates, l33t and dictionary matches, so there are no hand-rolled pattern detectors to get wrong. It ships as lazy chunks (about 1.6 MB, 0.8 MB gzipped), so the main bundle is unchanged |
| `@noble/hashes` 2.4.0 | Audited, zero-dependency hashing. **Web Crypto cannot stream:** `digest()` needs the whole input in memory and has no `update()`, so a 4 GB ISO cannot be hashed with progress. Web Crypto also has no MD5. noble provides incremental SHA-2, SHA-1 and MD5. Text hashing still uses Web Crypto (the spec's preference), and a test cross-checks the two implementations |

JWT signature verification uses Web Crypto only: HMAC, RSASSA-PKCS1-v1_5,
RSA-PSS, ECDSA P-256/384/521 and Ed25519.

The production build contains no `eval` or `new Function`, so the nginx CSP
(`script-src 'self'`) still holds. The vendored dictionaries are served from
our own origin.

### 5. Tool-specific choices

- **Password analyzer:**
  - Shows charset entropy (`length × log2(pool)`, counted in code points)
    beside the zxcvbn estimate, and explains the gap when it exceeds 10 bits.
  - Crack times are **ranges** for three named scenarios (online rate-limited,
    offline slow hash, offline fast hash) with their assumptions printed.
  - Pattern tokens are masked while the password is hidden.
  - The HIBP k-anonymity check is "optional future" in the spec and is **not
    implemented**: it would be the only network call in these tools.
- **JWT inspector:**
  - Findings use the backend severity scale with a rationale and a fix. They
    cover `alg: none` (CRITICAL), embedded `jwk` (HIGH), sensitive payload
    keys (HIGH), `jku`/`x5u` (MEDIUM), a missing `exp` (MEDIUM), long
    lifetimes and injection-looking `kid` values.
  - Verification takes the algorithm from the header but **checks the key
    type against it**. A PEM or JWK public key offered as an HMAC secret is
    refused as the algorithm-confusion attack. Private keys (PEM, or a JWK
    with `d`) are refused with a warning.
  - HMAC secrets shorter than the hash output get a warning (RFC 7518 §3.2).
- **Hash tool:**
  - Files are read with `File.stream()` (falling back to bounded slices) in
    one pass for every selected algorithm, yielding between chunks, with
    progress and cancel. The cap is 4 GiB.
  - Comparison normalises case, whitespace, `algo:`/`0x` prefixes and
    `sha256sum` output, then uses a constant-time compare. When the digest
    length points to an algorithm that isn't selected, it says so.
- **Encoder:**
  - Base64, Base64URL, URL encoding and hex are hand-written over UTF-8
    bytes. `btoa`/`atob` would mangle non-ASCII text.
  - Error messages give the position of the bad character and hints such as
    "this looks like Base64URL".
  - A suggestion appears only when the input decodes cleanly to mostly
    printable text, so ordinary words do not trigger false hits.
  - A round-trip check flags non-canonical input. Binary output is shown as
    hex.

## Consequences

- **CI cost:** the password tests load the real dictionaries, so the vitest
  per-test timeout is raised to 15 s.
- **Rule for future local tools:** add them to `LOCAL_TOOLS` and to the
  `ENTRIES` list of the static isolation test.
