# ADR 0014 — Log analyzer, uploads and the path guard

- **Status:** Accepted
- **Date:** 2026-10-04
- **Phase:** 10 (built after 12–14 and 8, as approved in ADR 0009)

## Context

02-modules.md, tool 5:
- input is an upload (size-capped, streamed) **or** a file inside a read-only
  `LOG_ROOT`, with the path guard applied;
- parser plugins `auth_log` (OpenSSH) and `nginx_access` (combined), with
  unrecognised lines counted, not fatal;
- detection rules as YAML data: SSH bursts, invalid-user enumeration, success
  after failures, root logins, path traversal, scanner user agents, high
  request rate, 4xx/5xx spikes;
- per detection: first and last timestamp, source IP, event type, count,
  severity with a rationale, explanation and remediation;
- line-by-line streaming, never the whole file in memory.

04-security.md section 5 asks for a central `PathGuard`, uploads stored under a
random name, size-capped, never executed and deleted after processing.

Acceptance (05-phases.md): sample auth.log and nginx logs in `tests/fixtures`
yield the expected detections, the traversal tests pass, and a large file is
processed within memory bounds.

## Decisions

### 1. Uploads are a generic framework feature

Uploads are not log-analyzer code. A tool sets `accepts_upload = True`
(enforced at import: its params model must have an `upload_name` field), and
the generic route `POST /api/v1/tools/{tool_id}/runs/upload` serves it. FIM or
any later tool gets uploads without touching core code (rule 9).

- **Body:** the raw file, with the file name and the JSON parameters in the
  query string. This avoids a multipart parser, which would mean a new
  dependency (`python-multipart`). The browser streams a `File` body with
  `fetch` just as well.
- **Cheap checks before the first body byte:** the tool accepts uploads,
  `Content-Length` fits the limit, the parameters validate (the same
  field-level 422 as the JSON route), and the caller is an analyst.
- **Streaming with caps:** chunks are written in a worker thread (so a slow
  disk never stalls the event loop). The upload aborts, and the partial file is
  deleted, at the size limit (`LOG_UPLOAD_MAX_MB`, default 50) or the time
  limit (`UPLOAD_TIMEOUT_SECONDS`, default 120).
- **Atomic:** data goes to `<id>.part` (created `O_EXCL`, mode 0600) and is
  renamed to `<id>.upload` when complete.
- **Audit:** `tool.run.requested` gains `upload: {name, bytes}`. Tools can
  declare `request_audit_action`, which records a domain event with the
  request: here `log.analysis.requested` (03-logging-audit.md), with the name
  and size, never the contents.

### 2. The stored file is named after the run id

The route generates the run id first, stores the file as `<run id>.upload` in
`UPLOAD_DIR` (a named volume shared by the API and the worker), and only then
creates the run with that id (`RunService.create(run_id=...)`). Consequences:

- **Nothing the user sends becomes a path.** The file name is display-only
  metadata, cleaned of directory parts and unusual characters.
- **A run can only open its own file.** The framework puts
  `ctx.upload_path` on the tool context from the run id. A forged run with an
  `upload_name` but no upload of its own finds nothing. An integration test
  proves another run's file stays untouched.
- **No race:** the file exists before the run is queued.
- **Cleanup belongs to the framework:**
  - The Celery task's `finally` deletes the file whatever the outcome:
    completed, failed, cancelled while queued, or timed out.
  - The route deletes it if run creation fails (quota, scope, validation).
  - Files older than an hour are swept on the next upload. That catches runs
    whose worker was killed by the hard limit.

### 3. PathGuard (`app/core/security/paths.py`)

1. **Syntactic checks** first, also used by the params validator for a clear
   422: null bytes, control characters, absolute paths, drive letters,
   backslashes, `..` segments and length.
2. **`resolve(strict=True)`:** symlinks followed and `..` collapsed; a missing
   file is a 404.
3. **Containment:** the resolved path must lie inside the resolved root. This
   is what stops symlinks out of the root.
4. **Open with `O_NOFOLLOW`,** then `fstat` and re-check containment on the
   open file, which narrows the TOCTOU window. A file swapped for a symlink
   after step 2 is refused (tested).

Encoded input is never decoded here: `..%2f` is a literal, non-existent name.
`LOG_ROOT` is mounted read-only into the worker only; the API never reads it.
An empty `LOG_ROOT` disables the source. Without that rule it would parse as
`Path(".")`, the app directory, so a validator turns it into `None`.

### 4. Parsing and detection

- **Parsers** declare their format and regexes, which are shown in the raw
  output. The regexes are anchored and have no nested quantifiers, and lines
  are capped at 8 KB, so matching time is linear in line length.
  - `auth_log` reads classic syslog (the year is inferred, so a log that spans
    New Year works) and RFC 3339 lines from `sshd` and `sshd-session`.
  - `nginx_access` reads the combined format and keeps malformed request lines
    (scanners send TLS bytes to HTTP ports).
  - **Auto-detection** scores the first 200 lines and picks the parser with the
    most events.
- **Rules** (`rules.yaml`, `yaml.safe_load`, Pydantic-validated, 200 KB cap)
  choose one of five built-in detectors: burst, distinct, sequence, match and
  spike.
  - Matching uses plain string comparison and a fixed traversal decoder (up to
    three URL-decoding rounds, plus overlong UTF-8 and `%u` forms). There are
    no regexes from YAML, so a rule edit cannot introduce catastrophic
    backtracking.
  - Thresholds live in YAML; explanation, remediation and severity rationale
    live in the knowledge base, as for every tool.
- **Severity** follows criteria documented in `knowledge/log_analyzer.yaml`.
  An attempt is rated lower than evidence that it may have worked, and each
  escalation has its own knowledge entry so the rationale always matches:
  - success after failures is HIGH;
  - a root login that succeeded is HIGH (failed attempts are MEDIUM);
  - traversal answered with 2xx is HIGH (rejected attempts are MEDIUM);
  - a 5xx-dominated spike is MEDIUM (a 4xx spike is LOW).

### 5. Bounded memory and time

- **Reader:**
  - one line at a time; a longer line is cut and the rest skipped in 64 KB
    chunks;
  - at most `LOG_ANALYZER_MAX_LINES` lines (2,000,000);
  - gzip recognised by magic bytes, with decompressed output capped at 20× the
    upload limit (zip bombs);
  - invalid UTF-8 replaced, not fatal.
- **Detectors:**
  - at most 50,000 tracked source addresses per rule; beyond that the result
    is marked partial (`too_many_sources`);
  - per-address windows hold at most 4× the threshold;
  - samples capped at 3 per address and 200 characters each.
- **Translator:** at most 25 findings per rule, plus one grouping finding for
  the rest.
- **Test:** 10× the input does not mean 10× the memory, and peak memory stays
  under a quarter of the file size (`tracemalloc`).
- **Time:** the analysis is CPU-bound, so it yields to the event loop every
  5,000 lines. That is what lets the framework's soft limit (120 s) and
  cooperative cancellation interrupt it; the hard limit is 150 s.

### 6. Untrusted log content

Log lines are attacker-controlled. Evidence samples have control characters
replaced and are truncated. Text is always rendered escaped (React, the PDF
exporter's `_esc`, the CSV formula guard). Log contents are never written to
the application log or the audit trail.

### 7. Deployment

- **Image:** creates `/data/uploads` owned by the unprivileged user (mode
  0700). A new named volume inherits that, and `/data/logs` stays root-owned
  and read-only.
- **Dev and prod compose:** the `uploads` volume on the API and worker;
  `${LOG_ROOT_HOST:-./backend/tests/fixtures/logs}:/data/logs:ro` on the worker
  only. The production profile re-adds both after its `volumes: !reset`.
- **Production nginx:** an upload location with `client_max_body_size 55m`,
  `proxy_request_buffering off` and 180 s timeouts, listed before the generic
  API location.

## Alternatives considered

- **Multipart uploads.** They need `python-multipart`, and they spool to temp
  files the framework does not control. Rejected under the minimal-dependency
  rule.
- **Upload first, then reference an upload id in run params.** That needs
  ownership records and a reuse policy for upload ids. Naming the file after
  the run id needs neither.
- **Regexes in rules.yaml.** More flexible, but a ReDoS risk in an operator-
  editable file. Built-in matchers cover the spec.

## Consequences

- Phase 11 (FIM) can reuse `PathGuard` and, if needed, the upload route.
- Raising the upload limit means raising `LOG_UPLOAD_MAX_MB` and the nginx
  `client_max_body_size` together (documented in `.env.example`).
- More formats (Apache error log, Windows events) are one parser module each.
