# ADR 0015: File Integrity Monitor

- **Status:** Accepted
- **Date:** 2026-10-05
- **Phase:** 11. Built in parallel with Phase 9 (amendment to ADR 0009). Issue #27.

## Context

02-modules.md, tool 6:

- Paths are restricted to a `FIM_ROOTS` allowlist, mounted read-only into the
  worker. The path guard applies, and symlinks are not followed out of a root.
- **Baseline:** SHA-256 plus size, mtime, mode and owner uid/gid for every
  file, stored in `fim_baselines` and `fim_baseline_entries`, with who created
  it and when.
- **Compare:** MODIFIED, ADDED, REMOVED and METADATA_CHANGED (permissions or
  owner), with severity from configurable path-sensitivity patterns.
- **Bounds:** chunked hashing, file count and size limits, exclude patterns,
  progress reporting.
- **Schedule:** optional scheduled checks through Celery beat.

Acceptance (05-phases.md): tests detect modified, added, removed and
permission-changed files, and symlink escape is blocked. ADR 0009 also requires
`beat` in the production profile, a demo on a named volume (not a Windows bind
mount), and a test that the Phase 13 exporters render the findings.

FIM is the first tool with durable state of its own: a check needs a baseline
that an earlier run created.

## Decisions

### 1. Two tools, one package

`app/tools/fim/` registers two tools:

| Tool | Parameters | Result |
|---|---|---|
| `fim_baseline`: Create FIM Baseline | `name`, `root`, `path`, `exclude` | The baseline is stored; findings summarise it and flag risky permissions already present |
| `fim_check`: File Integrity Check | `baseline_id` | One finding per change since the baseline |

Both are ordinary tool runs. They reuse the framework's validation, quotas,
progress over WebSocket, cancellation, soft and hard time limits, audit trail,
run history and report export, so none of that is written again for FIM.

A separate "create baseline" API with its own Celery task was rejected. It
would need its own status tracking, polling, limits and audit wiring.

### 2. State goes through a narrow store protocol

Tools never touch the database directly (`ToolContext`). As with
`app/core/external.py` (`Cache` and `WindowLimiter` for the threat-intel and
NVD tools), the FIM tools depend on a small protocol, `BaselineStore`, with
three methods: `save`, `load` and `record_check`. The SQL implementation lives
in the domain module `app/fim/store.py`. Unit tests use an in-memory fake, so
the scanning and comparison logic is tested without Postgres.

- **Attribution comes from the run, not from parameters.** `save(run_id, ...)`
  reads the run's user from `tool_runs`, so a baseline's `created_by` can
  never be forged.
- **Audit events:** the store records `fim.baseline.created` in the same
  transaction as the rows, and `fim.check.completed` with the change counts.

### 3. Data model (migration 0007)

- **`fim_baselines`:**
  - name, root name, relative path and excludes;
  - counts and total hashed bytes;
  - creator (id and username snapshot), creating run, and created time;
  - schedule (`schedule_minutes`, `last_scheduled_at`);
  - last check (time, run and change count);
  - soft delete (`deleted_at`, `deleted_by`).
- **`fim_baseline_entries`:** (baseline, path) as the primary key, plus kind
  (file, dir, symlink or other), size, `mtime_ns`, mode, uid, gid, sha256
  (null if not hashed), link target and a note (`unreadable`, `too_large`).
- **Grants for the app role:**
  - baselines: SELECT, INSERT and UPDATE, but **no DELETE**. A deleted
    baseline keeps its row as a record of who watched what.
  - entries: SELECT, INSERT and DELETE. Deleting a baseline drops its
    entries, which can be tens of thousands of rows.

### 4. Roots and the path guard

- **Configuration:** `FIM_ROOTS` is a list of named roots, `name=/abs/path`,
  comma-separated, at most 10. The default is `demo=/data/fim/demo`.
- **Root names, not paths:** users pick a root by name. The schema's `enum` is
  filled from settings when the catalogue is generated, so the form shows a
  drop-down. Server paths never reach the browser.
- **Validation:** the optional subdirectory passes `check_relative_path`
  (ADR 0014). Resolving it must stay inside the resolved root, and the result
  must be a real directory.
- **API and worker:** the API gets `FIM_ROOTS` to validate names; only the
  worker mounts the directories, read-only. An empty `FIM_ROOTS` makes both
  tools report themselves unavailable.

### 5. Scanning without following anything

- **Walk:** `os.scandir` with `follow_symlinks=False` everywhere. A symlink is
  recorded as a symlink: its target text is stored and compared, never
  followed. This is how symlink escape is blocked: a link to `/etc/shadow`
  inside the root is a `symlink` entry, and nothing outside the root is ever
  read. Tested.
- **Hashing:** files are opened with
  `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, then checked with `fstat`.
  - The open file must still be a regular file with the same device and inode
    as the directory listing saw. A file swapped between listing and opening
    is noted, not read.
  - `O_NONBLOCK` means a FIFO planted in the root cannot hang the worker.
  - Sockets, devices and FIFOs are recorded as `other` and never opened.
- **Chunks:** 1 MiB at a time.
- **Limits** (all in settings):

  | Setting | Default | What happens at the limit |
  |---|---|---|
  | `FIM_MAX_FILES` | 20,000 entries | Baseline creation refuses ("narrow the path or add excludes"). A check stops walking and marks the result partial; REMOVED is then not reported, because "not seen" is not "gone" |
  | `FIM_MAX_FILE_MB` | 100 MB | Larger files keep metadata only (`too_large`) and are compared by size and mtime |
  | `FIM_MAX_TOTAL_MB` | 2,048 MB hashed per run | Same treatment as the file limit |
  | Directory depth | 32 levels | |
  | Excludes | 32 patterns of up to 200 characters | |

- **Threading:** the walk runs in a worker thread so the event loop stays
  free. Every 0.5 s the async side reports progress and checks for
  cancellation. Cancellation, the soft time limit (300 s) and any error set a
  stop flag, which the thread checks between files and between chunks, so it
  never keeps running after the run has ended.

### 6. Comparison and severity

- **Change types:**
  - MODIFIED: content (SHA-256), file type or symlink target changed. For a
    file that could not be hashed, a size or mtime change counts, with MEDIUM
    confidence.
  - METADATA_CHANGED: mode, uid or gid changed.
  - ADDED and REMOVED.
- **mtime-only changes** with an identical hash are counted as "touched" and
  not reported. Attackers can reset an mtime, so content is always hashed and
  mtime is never trusted alone.
- **Path sensitivity:** `sensitivity.yaml` lists patterns with a level and a
  reason, first match wins, and unmatched paths are LOW. Examples:
  - `etc/shadow` and `etc/sudoers*` are CRITICAL;
  - `etc/*` and `*.conf` are HIGH;
  - web roots are MEDIUM.

  Patterns are `fnmatch` globs on the root-relative path, where `*` also
  matches `/`. There are no regexes, for the same ReDoS reason as ADR 0014.
- **Severity:**
  - MODIFIED, ADDED and REMOVED take the path's level.
  - METADATA_CHANGED takes one level lower (minimum LOW), because a mode
    change alone is less often malicious.
  - **Escalations, taking the higher of the two:**

    | Change | Severity |
    |---|---|
    | Becomes world-writable | HIGH (CWE-732) |
    | Gains setuid or setgid, or is added with it | CRITICAL (MITRE ATT&CK T1548.001) |
    | Regular file replaced by a symlink | HIGH |

  - Each finding's rationale names the matching pattern, its reason and the
    escalation.
- **Output:** at most 200 change findings, most severe first, plus one
  grouping finding for the rest and an INFO summary. Raw output keeps at most
  500 changes.

### 7. Scheduled checks

- **Schedule:** a baseline can be checked every 15, 60, 360 or 1,440 minutes.
  Only its creator or an admin can set this
  (`PATCH /api/v1/fim/baselines/{id}`, audited as `fim.baseline.updated`).
- **Beat** sends `sentinel.fim.dispatch_scheduled` every minute. The task
  claims due baselines with a compare-and-set on `last_scheduled_at`, so a
  double delivery never starts two checks.
- **Runs:** each claimed baseline gets a normal `fim_check` run through
  `RunService.create`, attributed to the creator.
  - The audit details carry `trigger: schedule`.
  - Per-user rate quotas are skipped, since the schedule is the rate.
  - If the creator has been disabled or demoted below analyst, the schedule
    is cleared instead of running under their name.
- **`beat` service:** a new compose service in dev and prod with the same
  image, no ports, a read-only root filesystem in prod and its schedule file
  on `/tmp`. Beat only publishes messages; it never reads FIM roots.

### 8. Baseline management API

| Route | Role | Notes |
|---|---|---|
| `GET /api/v1/fim/baselines` | viewer | Non-deleted baselines, newest first, capped at 200 |
| `PATCH /api/v1/fim/baselines/{id}` | analyst | Schedule only; creator or admin |
| `DELETE /api/v1/fim/baselines/{id}` | analyst | Creator or admin; soft delete, `fim.baseline.deleted` |

A denial for a non-creator is a 403 audited as `auth.access.denied`, as for
run cancellation.

### 9. Frontend

- **Forms:** both tools use the generated form. `exclude` is a comma-separated
  string, because the form supports flat fields only.
- **Panel:** `REMOTE_TOOL_META` gains an optional `panel`. The FIM tools use it
  to show a baselines panel under the form, with Check now, a schedule
  selector and Delete. That is one registry entry, no route or layout change
  (rule 9).

### 10. Demo on a named volume

- **The `fim_demo` volume:**
  - The worker mounts it read-only at `/data/fim/demo`.
  - The `lab-fim` service (lab profile, no network, all capabilities dropped,
    non-root) mounts it read-write and seeds a small fake filesystem: `etc/`,
    `usr/local/bin`, `var/www` and `home/app/.ssh`.
- **Demo:** run
  `docker compose exec lab-fim sh /opt/fim/tamper.sh`
  to modify, add, remove and chmod files, then check again.
- **Why a named volume:** Windows bind mounts lose POSIX modes and owners.

## Alternatives considered

- **Store baseline entries as JSON in `raw_data`.** That is capped at 1 MB,
  can't be queried, and mixes evidence with state. Rejected.
- **Watch roots continuously (inotify).** That needs a long-lived process per
  root and doesn't survive restarts. The spec asks for baseline comparison.
  Rejected.
- **Report mtime-only changes.** Too noisy (backups, `touch`). They are counted
  in the summary instead.

## Consequences

- Phase 9 and later tools can use the `panel` hook for tool-specific UI.
- Raising `FIM_MAX_FILES` costs database rows: about 150 bytes per entry.
- Real host paths can be monitored by adding a read-only bind mount and a
  `FIM_ROOTS` entry. On Docker Desktop for Windows, modes and owners of bind
  mounts are not meaningful, so use a named volume or a Linux host.
