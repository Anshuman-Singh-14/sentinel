# ADR 0009 — Playbook engine, and building Phases 12–14 before 8–11

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 12

## Part A — Phase order

### Decision

Approved by the project owner on 2026-10-02. The remaining phases are built
in this order:

**12 → 13 → 14 → 8 → 10 → 11 → 9**

The spec order is 8 → 9 → 10 → 11 → 12 → 13 → 14.

**Amendment (2026-10-05, approved by the project owner):** a second developer
joined. With 12, 13, 14, 8 and 10 merged, **Phases 11 and 9 are built in
parallel**, one per developer. They are separate tool modules with no
dependency on each other. The optional observability profile (the deferred
part of Phase 14, ADR 0011) follows Phase 11 on the same developer's side.
Collisions on shared files are handled by `docs/COLLABORATION.md`. Reserved
numbers:

| Work | Issue | ADR | Threat IDs |
|---|---|---|---|
| Phase 11 (FIM) | #27 | 0015 | T78–T84 |
| Observability profile | #32 | 0016 | T85–T89 |
| Phase 9 (network diagnostics) | #28 | 0017 | T90–T99 |

### Why

The capstone review is at the end of November. The MVP cut line in
PROGRESS.md already marks 12 (Playbooks) and 13 (Reports) as core and 8–11
as stretch. Building the core first guarantees a complete, polished demo
(playbook → report, README, production setup) before the review. Stretch
phases then use whatever time is left, ordered by demo value.

### Why the reorder is safe (dependency check)

| Depends on | What breaks if the dependency is missing | Mitigation |
|---|---|---|
| Phase 12 needs 5–7 | Nothing: all built | — |
| The Web Defensive Audit's Threat Intel step (Phase 8) | The step would fail | `optional: true`. A missing tool means the step is SKIPPED ("not installed yet"), and it activates automatically once the tool registers |
| The spec's "→ Report" step (Phase 13) | — | Phase 13 adds export of playbook runs. 13 still comes right after 12, so the natural order holds |
| Phase 14 (polish) before 8–11 | The README and production setup would not mention later tools | Each deferred phase must follow the checklist below |

### Checklist for each deferred phase (8, 10, 11, 9) when it lands

1. **Phase 8:**
   - Register `threat_intel`. Its parameters must accept the playbook's
     reference `indicators: "{{ steps.dns.resolved_ips }}"`. If the
     parameter name differs, update `web_defensive_audit.yaml` too.
   - Add an integration test showing the step now runs.
2. **All of them:**
   - Make sure the Phase 13 exporters render the new tool's findings. They
     take generic `Finding`s, so this should need no change; verify with a
     test.
   - Update the README tool list and screenshots (Phase 14 artefacts).
3. **Phase 11:** the `beat` scheduler service must also be added to the
   production compose profile created in Phase 14.
4. **Phase 9:** if the worker needs `NET_RAW`, apply it to the production
   profile as well, and document the trade-off.

## Part B — Playbook engine

### Definitions

YAML lives in `app/playbooks/definitions/`. It is loaded with
`yaml.safe_load`, capped at 200 KB and validated by Pydantic
(`PlaybookDefinition`):

- **Inputs** have a kind: `host`, `domain`, `url` or `string`. Each kind is
  validated by the same validators the tools use; `url` goes through the
  SSRF guard's URL rules. A default may reference *earlier* inputs.
- **Steps** have a `tool_id`, `params`, `on_failure: stop | continue` and
  `optional`.
- **Load-time checks:** every reference must name a known input or an
  *earlier* step, step ids must be unique, and unknown keys are rejected. A
  broken definition fails at startup, never mid-run.

### Safe references (`templating.py`)

Supported forms: `{{ inputs.x }}` and `{{ steps.<id>.<field>[n] }}`.

- References are parsed by a strict regular expression and walk **plain JSON
  only** (dict keys, list indexes).
- There is no template engine: no filters, calls, arithmetic, negative
  indexes or attribute access. `__class__`, `__import__` and similar are
  plain missing keys.
- A whole-value reference keeps its type (a list stays a list). An embedded
  reference must resolve to a scalar.
- Rendered strings are capped at 4 KB.

### Execution

- **One orchestrator task** per playbook run (`sentinel.run_playbook`, queue
  `scans`) runs the steps **sequentially and in-process**.
  - Each step is created through `RunService.create(..., playbook_run_id=...)`,
    so it gets the same role, parameter, acknowledgement and scope checks and
    the same audit trail as a manual run.
  - Each step is then executed with the same `execute_run`, which includes
    the authoritative worker scope check, persistence, progress and timeouts.
  - A step is a normal `ToolRun`, linked both ways.
- **Why not sub-tasks or a chain:** a task that waits on other tasks can
  deadlock a small worker pool, and Celery warns against it. Inline execution
  keeps ordering, references and cancellation deterministic. The spec asks
  for sequential v1 with room for parallel steps later.
- **Re-checked per step:** the API pre-checks the target's scope once, and
  every step re-checks its own target. A playbook therefore cannot be used to
  launder an out-of-scope target through a later step.
- **Quotas:** starting a playbook counts against the per-minute, per-hour and
  concurrent caps. Its own steps are not counted twice; manual runs and
  playbooks share the concurrent cap.
- **Time limits:** Celery's limits are the sum of the steps' hard limits plus
  margins. Each step still has its own in-process limit (TIMED_OUT).
- **Redelivery:** a playbook found RUNNING on redelivery (the worker died) is
  failed (`worker_lost`), never silently re-run.

### Step outcome rules

- **Tool not installed:** an optional step is SKIPPED (`tool_not_installed`);
  a required one is FAILED. Playbooks with a missing *required* tool are
  reported unavailable and refused at start (409).
- **Unresolvable reference:** the step FAILED (`reference_error`).
- **Refused by the run service** (validation, scope, authorisation): the step
  FAILED with that error, and the message includes the first field-level
  reason.
- **Failure handling:** a FAILED or TIMED_OUT step with `on_failure: stop`
  stops the playbook, which ends FAILED with `step_failed`; the remaining
  steps are SKIPPED (`stopped`). With `continue`, the playbook carries on.
- **Cancellation:**
  - A queued playbook is cancelled outright.
  - A running playbook gets a Redis flag, checked before every step. It is
    also forwarded to the running step's tool through the progress relay, so
    the tool stops cooperatively. The remaining steps become CANCELLED.
- **Late cancel:** a playbook that finishes before it notices a cancel keeps
  its real outcome. This was observed live: a 320 ms playbook completed just
  as the cancel landed.

### Results

**Unified findings** are computed on read from the step runs' findings, so
they can never drift from their sources:

- Merged and **de-duplicated** by (category, item, severity),
  case-insensitively.
- The first reporting step keeps the finding; later ones are listed in
  `also_reported_by`.
- Ranked by severity, stable within a level.

The **risk summary** gives the highest severity, counts and a plain-language
headline, and flags partial coverage when steps failed.

### Live progress

- The orchestrator publishes `playbook.update` snapshots (overall percentage,
  each step's status) on `sentinel:playbook:{id}`.
- `/ws/playbooks/{id}` relays them, sharing one hardened relay with runs.
- **WebSocket tickets** now carry a *kind*, so a tool-run ticket cannot open a
  playbook stream, or the reverse.

### Data (migration 0005)

- New tables `playbook_runs` and `playbook_steps`. The app role may SELECT,
  INSERT and UPDATE; there is no DELETE, because history is evidence.
- `tool_runs.playbook_run_id` links each step's run to its playbook run.

## Consequences

- **Acceptance verified live against the lab:**
  - The Web Defensive Audit streamed QUEUED → RUNNING 0/25/50/75% →
    COMPLETED, with each step's status shown live.
  - The DNS step failed for the internal name `lab-https` and the playbook
    continued, showing `on_failure: continue`.
  - The Threat Intel step was SKIPPED as not installed.
  - The self-signed certificate (HIGH) topped 11 unified findings.
  - Cancelling a run against a slow in-scope target left it CANCELLED, with
    the remaining steps CANCELLED.
- **Integration tests** cover:
  - references between steps;
  - optional skip;
  - unified findings with provenance;
  - `on_failure` stop and continue;
  - reference errors;
  - cancel queued and cancel mid-step (propagated into the tool);
  - redelivery;
  - availability (409), roles, input validation;
  - acknowledgement and scope at start;
  - the shared quota;
  - WebSocket ticket kinds;
  - grants.
