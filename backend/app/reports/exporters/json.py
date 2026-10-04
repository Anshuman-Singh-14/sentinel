"""JSON exporter: the complete report document, including raw tool output.

The machine-readable twin of the PDF: same findings, same provenance, plus
the full raw data (each run's raw output was already capped at storage).
"""

from app.reports.document import ReportDocument
from app.reports.exporters.base import Exporter, register


@register
class JsonExporter(Exporter):
    format = "json"
    label = "JSON"
    media_type = "application/json"
    extension = "json"

    def render(self, doc: ReportDocument) -> bytes:
        return doc.model_dump_json(indent=2).encode("utf-8")
