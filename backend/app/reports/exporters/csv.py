"""CSV exporter: one row per finding, formula-injection safe (see ``csv_safe``)."""

import json

from app.reports.csv_safe import write_csv
from app.reports.document import ReportDocument
from app.reports.exporters.base import Exporter, register

HEADER = (
    "finding",
    "severity",
    "confidence",
    "status",
    "category",
    "item",
    "source",
    "also_reported_by",
    "target",
    "explanation",
    "severity_rationale",
    "remediation",
    "references",
    "evidence",
    "run_id",
)


@register
class CsvExporter(Exporter):
    format = "csv"
    label = "CSV"
    media_type = "text/csv; charset=utf-8"
    extension = "csv"

    def render(self, doc: ReportDocument) -> bytes:
        rows = [
            (
                f"F-{number:02d}",
                f.severity.value,
                f.confidence.value,
                f.status.value,
                f.category,
                f.item,
                f.step_id,
                " | ".join(f.also_reported_by),
                doc.subject.target or "",
                f.explanation,
                f.severity_rationale,
                f.remediation,
                " | ".join(f.references),
                json.dumps(f.evidence, sort_keys=True, default=str, ensure_ascii=False)
                if f.evidence
                else "",
                str(f.run_id),
            )
            for number, f in enumerate(doc.findings, start=1)
        ]
        return write_csv(HEADER, rows)
