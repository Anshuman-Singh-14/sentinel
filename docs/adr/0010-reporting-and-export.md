# ADR 0010 — Reporting and export

- **Status:** Accepted
- **Date:** 2026-10-04
- **Phase:** 13
- **Supersedes:** the Phase 13 design note (`docs/plans/phase-13-reporting.md`, removed)

## Context

Phase 13 turns a finished tool run or playbook run into a shareable report
(PDF, CSV, JSON, plain text), keeps a history of reports, and lets admins
export the audit trail (deferred from Phase 3). Acceptance: a professional
PDF for a playbook run, a passing CSV-injection test, and audited exports.

Report content is hostile by nature: service banners, HTTP headers, DNS
records, user agents and usernames are all chosen by someone else.

## Decision

### One document, many exporters

Every report is built first as a `ReportDocument` (`app/reports/document.py`):
subject (what, which version, target, who ran it and when), tools and
versions, playbook steps, the risk summary, findings with their source step,
errors, and raw data. For playbooks the findings and risk come from
`load_detail`, the same function the run page uses, so the PDF and the
screen can never disagree.

Exporters are plugins (`app/reports/exporters/`): a class with `format`,
`label`, `media_type`, `extension` and a pure `render(doc) -> bytes`, added
with `@register` and one import line. `GET /reports/formats` publishes the
registry, and the frontend's export buttons are built from it, so a new
format needs no frontend change (CLAUDE.md rule 9). A test keeps the
registry and the database CHECK constraint in sync.

### Generation runs in a worker

`POST /reports` validates the request, requires the source run to be
finished, applies quotas, writes the report row (QUEUED) together with its
`report.exported` audit event, and then sends `sentinel.generate_report`
with the report id only. The worker claims the row with a compare-and-set,
builds the document, renders it in a thread under a timeout, stores the file
in `report_blobs`, records size and SHA-256, and audits `report.generated`
in the same transaction. A redelivered message for a RUNNING report is
failed (`worker_lost`), not rendered twice. This is the same lifecycle as a
tool run (ADR 0006).

The file is stored in Postgres (`bytea`, separate table) rather than on a
volume. A blob in the database is covered by backups, transactions and the
grants model, and needs no shared filesystem between api and worker. The
20 MB cap keeps that sensible.

### Downloads are verified and audited

`GET /reports/{id}/download` re-hashes the stored bytes and refuses to serve
them if they do not match the recorded SHA-256 (500 `integrity_failed`,
audited as a security event). Every download is audited before the bytes
leave; if the audit write fails, the download fails closed. Responses are
attachments with a server-built ASCII filename, `Cache-Control: no-store`,
and the API's `default-src 'none'` CSP.

### Who can do what

Analysts and admins request reports; every role can list and download them.
This matches runs, which every role can read (03-logging-audit.md:
"analyst: run tools/playbooks, export; viewer: read results"). The audit
export is admin-only.

### Output safety

- **PDF (ReportLab):** every dynamic string passes through
  `xml.sax.saxutils.escape` before a `Paragraph`, raw data is rendered with
  `Preformatted` (no markup parsing), and references are printed, not linked.
  Tests feed `<a href="javascript:...">`, `<img>` and `<font>` through every
  field and assert that the PDF has no annotations, URI or JavaScript
  actions.
- **CSV:** cells starting with a formula trigger (`= + - @`, tab, CR, LF,
  full-width look-alikes, also after leading whitespace) get a leading
  apostrophe; every cell is quoted; cells are capped. The audit export
  uses the same writer, because usernames, user agents and targets in the
  audit trail are attacker-influenced.
- **All formats:** control characters are stripped and text is NFC-normalised.

### Audit-trail export

`GET /admin/audit/export?format=csv|json` takes the audit viewer's filters,
returns newest first, and is capped at `AUDIT_EXPORT_MAX_ROWS` (10,000).
Truncation is reported in the JSON body and in `X-Export-Truncated`.
`audit.exported` records the format, row count, id range and filters. It is
a GET (like every download, so the browser can save it) and synchronous:
10,000 rows render in well under a second, so a task would add latency and
no safety.

## Alternatives considered

- **HTML templates rendered to PDF (WeasyPrint, headless Chrome):** nicer
  typography, but they render HTML, which is exactly what 04-security.md
  rules out for untrusted content. They are also heavy native dependencies.
- **Rendering in the API process:** simpler, but a large playbook PDF would
  tie up an API worker. The worker queue already has time limits and
  backpressure.
- **Storing files on a volume:** needs a volume shared by api and worker,
  with its own permissions, cleanup and backup story.

## Consequences

- New dependency: `reportlab==5.0.1` (pulls in `pillow`). ReportLab has no
  type stubs, so mypy ignores its imports.
- Migration 0006: `reports` (SELECT, INSERT, UPDATE) and `report_blobs`
  (SELECT, INSERT) for the app role, and no DELETE on either. Report history
  is evidence of what was disclosed. Retention and cleanup of old reports
  are not implemented yet.
- PDFs use the built-in Helvetica and Courier fonts: non-Latin-1 characters
  render as boxes in the PDF only. The other formats keep them.
- `risk_summary` gained a `unit` argument ("step" or "run"), so a single-run
  report does not talk about "steps".
- Threat model rows T58–T63.
