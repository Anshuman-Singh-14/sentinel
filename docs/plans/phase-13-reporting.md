# Phase 13 — Reporting & Export: design (not yet implemented)

Status: design only. This branch (`feat/phase-13-reporting`) has no code yet.

## Acceptance (05-phases.md)

- A professional PDF for a playbook run.
- The CSV-injection test passes.
- Exports are audited.

## Dependency

**reportlab 5.0.1**, which pulls in pillow and charset-normalizer. Pin it, then relock with
uv in Docker as in earlier phases.

## Design

- **Model `reports`:** id, source_type (`tool_run` | `playbook_run` | `audit`), source_id,
  params JSONB (the audit filters), format (`pdf` | `json` | `csv` | `txt`), status
  (`QUEUED` | `RUNNING` | `COMPLETED` | `FAILED`), user_id, username, created_at,
  completed_at, size_bytes, sha256, filename, error.
- **Model `report_blobs`:** report_id (PK, FK) and content `bytea`, capped at about 20 MB.
- **Grants:** both tables get SELECT and INSERT; `reports` also gets UPDATE.
- **`app/reports/document.py`:** builds a normalised `ReportDocument` (metadata, tools and
  versions, steps, risk summary, findings with their source step, errors, truncated raw
  data) from a ToolRun or PlaybookRun. Reuse `playbooks.aggregate`.
- **`app/reports/exporters/`:** a plugin registry. Each exporter has `format`, `media_type`,
  `extension` and `render(doc) -> bytes`. There are four:
  - **pdf:** cover page, scope and metadata, executive summary with a severity bar chart
    (`reportlab.graphics`), findings table, detailed findings, steps, appendix, and
    "Page X of Y". All dynamic text is passed through `xml.sax.saxutils.escape` before it
    reaches a `Paragraph`. Raw data goes in `Preformatted`, which does no markup parsing.
    Never render untrusted HTML (04-security.md section 9).
  - **csv:** one row per finding. Cells starting with `= + - @ \t \r` get a `'` prefix to
    block formula injection.
  - **json:** the full ToolResult or playbook detail.
  - **txt:** plain text.
- **Celery task** `sentinel.generate_report(report_id)`: runs the exporter, stores the blob,
  records sha256 and size.
- **Audit events:**
  - The POST request: `report.exported` (or `audit.exported` for audit sources).
  - Task completion: `report.generated`.
  - Download: `report.downloaded`.
- **API:**
  - `POST /api/v1/reports` (analyst).
  - `GET /reports` and `GET /reports/{id}` (viewer).
  - `GET /reports/{id}/download`: attachment with a safe ASCII filename, `no-store`.
  - Admin `POST /admin/audit/export` (csv/json, filters, capped at 10k rows). This closes
    the item deferred from Phase 3.
- **Frontend:**
  - Export buttons (PDF/CSV/JSON/TXT) on the run and playbook run pages, polling until the
    report is ready, then a download link.
  - A `/reports` history page.
  - Audit page export.
- **Tests:**
  - Exporters, including the CSV-injection cases and PDF text escaping (a `<a href=javascript:>`
    in a banner must not become a link).
  - Integration: request → task → download, the audit trail, RBAC.
