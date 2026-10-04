"""PDF exporter (ReportLab platypus).

Layout: cover page, executive summary with a severity chart, scope and
method, findings overview, detailed findings, errors, and a raw-data
appendix, with "Page X of Y" on every page.

Security (04-security.md section 9, "PDF generation never renders untrusted
HTML"): ReportLab's ``Paragraph`` understands a small markup language
(``<a href>``, ``<img>``, ``<font>``...). Every piece of dynamic text goes
through ``_esc`` (``xml.sax.saxutils.escape``) before it reaches a
Paragraph, so a banner such as ``<a href="javascript:...">`` is printed as
text and never becomes a link, image or font change. The only markup in a
Paragraph is the literal tags written in this module. Raw data goes into
``Preformatted``, which does no markup parsing at all. References are
printed, not linked: a report must not carry clickable URLs chosen by a
scanned host.
"""

import math
from collections.abc import Callable
from functools import partial
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.document import ReportDocument
from app.reports.exporters._format import (
    RAW_SECTION_MAX_CHARS,
    RAW_TOTAL_MAX_CHARS,
    SEVERITY_ORDER,
    evidence_lines,
    fmt_dt,
    fmt_duration,
    raw_json,
    scalar,
    truncate,
)
from app.reports.exporters.base import Exporter, clean_text, register

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN
TEXT_MAX = 6000  # per paragraph; bounds a pathological finding

INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#475569")
RULE = colors.HexColor("#cbd5e1")
BAND = colors.HexColor("#0b1220")
ACCENT = colors.HexColor("#0e7490")
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#b91c1c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#1d4ed8"),
    "INFO": colors.HexColor("#475569"),
}
SEVERITY_MEANING = {
    "CRITICAL": "Exploitable now with serious impact. Fix immediately.",
    "HIGH": "Likely exploitable or a major weakness. Fix as a priority.",
    "MEDIUM": "A real weakness that needs other conditions to exploit. Plan a fix.",
    "LOW": "Hardening gap with limited impact. Fix when convenient.",
    "INFO": "Context or a passed check. No action needed.",
}


def _esc(value: object, limit: int = TEXT_MAX) -> str:
    """Untrusted text -> Paragraph-safe markup (escaped, newlines as <br/>)."""
    return escape(truncate(clean_text(value), limit)).replace("\n", "<br/>")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=INK,
        splitLongWords=True,
    )
    return {
        "body": body,
        "small": ParagraphStyle("Small", parent=body, fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("Cell", parent=body, fontSize=8.5, leading=11),
        "cell_head": ParagraphStyle(
            "CellHead",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=ACCENT,
            spaceBefore=4,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            spaceBefore=6,
            spaceAfter=8,
            textColor=INK,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            spaceBefore=10,
            spaceAfter=4,
            textColor=INK,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=29,
            textColor=INK,
            spaceAfter=6,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub", parent=body, fontSize=12, leading=16, textColor=MUTED, spaceAfter=18
        ),
        "badge": ParagraphStyle(
            "Badge",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=1,
        ),
        "mono": ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=7, leading=8.6),
    }


def _grid(rows: list[list[Any]], widths: list[float], *, header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), BAND))
    table.setStyle(TableStyle(commands))
    return table


def _kv(rows: list[tuple[str, str]], st: dict[str, ParagraphStyle]) -> Table:
    """Two-column label/value table. Labels are module constants; values are escaped."""
    data = [
        [Paragraph(f"<b>{label}</b>", st["cell"]), Paragraph(_esc(value), st["cell"])]
        for label, value in rows
    ]
    return _grid(data, [45 * mm, CONTENT_WIDTH - 45 * mm], header=False)


def _badge(severity: str, st: dict[str, ParagraphStyle], width: float = 22 * mm) -> Table:
    table = Table([[Paragraph(severity, st["badge"])]], colWidths=[width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(severity, MUTED)),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


def _severity_chart(counts: dict[str, int]) -> Drawing:
    drawing = Drawing(CONTENT_WIDTH, 60 * mm)
    chart = VerticalBarChart()
    chart.x, chart.y = 14 * mm, 9 * mm
    chart.width, chart.height = CONTENT_WIDTH - 20 * mm, 46 * mm
    chart.data = [[counts.get(sev, 0) for sev in SEVERITY_ORDER]]
    chart.categoryAxis.categoryNames = list(SEVERITY_ORDER)
    chart.categoryAxis.labels.fontName = "Helvetica-Bold"
    chart.categoryAxis.labels.fontSize = 8
    top = max([*counts.values(), 0])
    step = max(1, math.ceil(top / 5))
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(step * 5, step)
    chart.valueAxis.valueStep = step
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.gridStrokeColor = RULE
    chart.valueAxis.visibleGrid = True
    chart.bars.strokeColor = None
    chart.barLabelFormat = "%d"
    chart.barLabels.nudge = 6
    chart.barLabels.fontName = "Helvetica-Bold"
    chart.barLabels.fontSize = 8
    for index, sev in enumerate(SEVERITY_ORDER):
        chart.bars[(0, index)].fillColor = SEVERITY_COLORS[sev]
    drawing.add(chart)
    return drawing


class _NumberedCanvas(Canvas):
    """Defers page output until the end so every page can say "Page X of Y"."""

    def __init__(self, *args: Any, footer: str = "", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._pages: list[dict[str, Any]] = []
        self._footer = footer

    def showPage(self) -> None:
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            self.drawString(MARGIN, 10 * mm, self._footer)
            self.drawRightString(
                PAGE_WIDTH - MARGIN, 10 * mm, f"Page {self._pageNumber} of {total}"
            )
            super().showPage()
        super().save()


def _decorate(title: str) -> tuple[Callable[..., None], Callable[..., None]]:
    def first(canvas: Canvas, _doc: Any) -> None:
        canvas.saveState()
        canvas.setFillColor(BAND)
        canvas.rect(0, PAGE_HEIGHT - 32 * mm, PAGE_WIDTH, 32 * mm, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_HEIGHT - 33.5 * mm, PAGE_WIDTH, 1.5 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 20)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 19 * mm, "SENTINEL")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 25 * mm, "Defensive security assessment")
        canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 19 * mm, "CONFIDENTIAL")
        canvas.restoreState()

    def later(canvas: Canvas, _doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(INK)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 11 * mm, "SENTINEL")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        # Canvas text is drawn literally (no markup), so the title needs no escaping.
        canvas.drawString(MARGIN + 18 * mm, PAGE_HEIGHT - 11 * mm, truncate(title, 80))
        canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 11 * mm, "CONFIDENTIAL")
        canvas.setStrokeColor(RULE)
        canvas.line(MARGIN, PAGE_HEIGHT - 13 * mm, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 13 * mm)
        canvas.restoreState()

    return first, later


@register
class PdfExporter(Exporter):
    format = "pdf"
    label = "PDF"
    media_type = "application/pdf"
    extension = "pdf"

    def render(self, doc: ReportDocument) -> bytes:
        st = _styles()
        title = clean_text(doc.title)
        story: list[Flowable] = []
        story += self._cover(doc, st)
        story += self._summary(doc, st)
        story += self._scope(doc, st)
        story += self._overview(doc, st)
        story += self._details(doc, st)
        story += self._appendix(doc, st)

        buffer = BytesIO()
        template = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title=truncate(title, 200),
            author="Sentinel",
            subject=truncate(clean_text(doc.subject.target or ""), 200),
            creator="Sentinel",
        )
        first, later = _decorate(title)
        footer = truncate(f"Report {doc.report_id} - generated {fmt_dt(doc.generated_at)}", 120)
        template.build(
            story,
            onFirstPage=first,
            onLaterPages=later,
            canvasmaker=partial(_NumberedCanvas, footer=footer),
        )
        return buffer.getvalue()

    # --- sections ------------------------------------------------------------------

    def _cover(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        s = doc.subject
        kind = "Playbook run" if s.kind == "playbook_run" else "Tool run"
        highest = doc.risk.highest.value if doc.risk.highest else None
        story: list[Flowable] = [
            Spacer(1, 22 * mm),
            Paragraph(_esc(doc.title, 200), st["cover_title"]),
            Paragraph(f"Target: <b>{_esc(s.target or '-', 300)}</b>", st["cover_sub"]),
        ]
        if highest:
            story += [
                Table(
                    [
                        [
                            _badge(highest, st, 30 * mm),
                            Paragraph(_esc(doc.risk.headline), st["body"]),
                        ]
                    ],
                    colWidths=[34 * mm, CONTENT_WIDTH - 34 * mm],
                    style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]),
                ),
                Spacer(1, 8 * mm),
            ]
        else:
            story += [Paragraph(_esc(doc.risk.headline), st["body"]), Spacer(1, 8 * mm)]
        story.append(
            _kv(
                [
                    ("Assessment", f"{kind}: {s.name} (version {s.version})"),
                    ("Status", s.status),
                    ("Run by", s.initiated_by),
                    ("Started", fmt_dt(s.started_at)),
                    ("Completed", fmt_dt(s.completed_at)),
                    ("Duration", fmt_duration(s.duration_ms)),
                    ("Source ID", str(s.id)),
                    ("Report generated", f"{fmt_dt(doc.generated_at)} by {doc.generated_by}"),
                    ("Report ID", str(doc.report_id)),
                ],
                st,
            )
        )
        story += [
            Spacer(1, 10 * mm),
            Paragraph(
                "This report was produced by Sentinel, an educational and defensive platform. "
                "It describes checks run against a target the requester was authorised to "
                "assess. Each finding explains what was observed, why it matters, how its "
                "severity was decided and how to fix it. Automated checks can miss issues or "
                "report false positives: confirm findings before acting on them. Handle this "
                "document as confidential.",
                st["small"],
            ),
            PageBreak(),
        ]
        return story

    def _summary(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        counts = {str(k): v for k, v in doc.risk.by_severity.items()}
        story: list[Flowable] = [
            Paragraph("Executive summary", st["h1"]),
            Paragraph(_esc(doc.risk.headline), st["body"]),
            Spacer(1, 4 * mm),
            _severity_chart(counts),
            Spacer(1, 3 * mm),
        ]
        rows: list[list[Any]] = [
            [
                Paragraph("Severity", st["cell_head"]),
                Paragraph("Count", st["cell_head"]),
                Paragraph("What it means", st["cell_head"]),
            ]
        ]
        for sev in SEVERITY_ORDER:
            rows.append(
                [
                    _badge(sev, st),
                    Paragraph(str(counts.get(sev, 0)), st["cell"]),
                    Paragraph(SEVERITY_MEANING[sev], st["cell"]),
                ]
            )
        story.append(_grid(rows, [26 * mm, 16 * mm, CONTENT_WIDTH - 42 * mm]))
        top = [f for f in doc.findings if f.severity.value in ("CRITICAL", "HIGH")][:5]
        if top:
            story += [Paragraph("Priorities", st["h2"])]
            story += [
                Paragraph(f"<b>{_esc(f.item, 300)}</b>: {_esc(f.remediation, 400)}", st["body"])
                for f in top
            ]
        if doc.errors:
            story += [Paragraph("Errors and partial coverage", st["h2"])]
            story += [Paragraph(_esc(error, 600), st["body"]) for error in doc.errors]
        return story

    def _scope(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        story: list[Flowable] = [
            CondPageBreak(60 * mm),
            Paragraph("Scope and method", st["h1"]),
            Paragraph("Tools and versions", st["h2"]),
        ]
        rows: list[list[Any]] = [[Paragraph(h, st["cell_head"]) for h in ("Tool", "ID", "Version")]]
        rows += [
            [
                Paragraph(_esc(t.name), st["cell"]),
                Paragraph(_esc(t.tool_id), st["cell"]),
                Paragraph(_esc(t.version), st["cell"]),
            ]
            for t in doc.tools
        ]
        story.append(_grid(rows, [80 * mm, 60 * mm, CONTENT_WIDTH - 140 * mm]))
        story.append(Paragraph("Parameters", st["h2"]))
        if doc.subject.parameters:
            story.append(
                _kv(
                    [(clean_text(k)[:60], scalar(v)) for k, v in doc.subject.parameters.items()], st
                )
            )
        else:
            story.append(Paragraph("None.", st["body"]))
        if doc.steps:
            story.append(Paragraph("Playbook steps", st["h2"]))
            rows = [
                [Paragraph(h, st["cell_head"]) for h in ("#", "Step", "Tool", "Status", "Note")]
            ]
            rows += [
                [
                    Paragraph(str(step.position + 1), st["cell"]),
                    Paragraph(_esc(step.name), st["cell"]),
                    Paragraph(_esc(step.tool_id), st["cell"]),
                    Paragraph(_esc(step.status), st["cell"]),
                    Paragraph(_esc(step.error or "", 500), st["cell"]),
                ]
                for step in doc.steps
            ]
            story.append(_grid(rows, [8 * mm, 45 * mm, 32 * mm, 24 * mm, CONTENT_WIDTH - 109 * mm]))
        return story

    def _overview(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        story: list[Flowable] = [
            PageBreak(),
            Paragraph(f"Findings ({len(doc.findings)})", st["h1"]),
        ]
        if not doc.findings:
            return [*story, Paragraph("No findings were reported.", st["body"])]
        rows: list[list[Any]] = [
            [
                Paragraph(h, st["cell_head"])
                for h in ("#", "Severity", "Finding", "Category", "Source")
            ]
        ]
        for number, f in enumerate(doc.findings, start=1):
            rows.append(
                [
                    Paragraph(f"F-{number:02d}", st["cell"]),
                    _badge(f.severity.value, st),
                    Paragraph(_esc(f.item, 300), st["cell"]),
                    Paragraph(_esc(f.category), st["cell"]),
                    Paragraph(_esc(f.step_id), st["cell"]),
                ]
            )
        story.append(_grid(rows, [13 * mm, 25 * mm, CONTENT_WIDTH - 104 * mm, 36 * mm, 30 * mm]))
        return story

    def _details(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        if not doc.findings:
            return []
        story: list[Flowable] = [PageBreak(), Paragraph("Detailed findings", st["h1"])]
        for number, f in enumerate(doc.findings, start=1):
            source = _esc(f.step_id) + (
                f" (also reported by {_esc(', '.join(f.also_reported_by))})"
                if f.also_reported_by
                else ""
            )
            heading = Table(
                [
                    [
                        _badge(f.severity.value, st),
                        Paragraph(f"<b>F-{number:02d}  {_esc(f.item, 300)}</b>", st["body"]),
                    ]
                ],
                colWidths=[25 * mm, CONTENT_WIDTH - 25 * mm],
                style=TableStyle(
                    [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (0, 0), 0)]
                ),
            )
            meta = Paragraph(
                f"Status {_esc(f.status.value)} | Category {_esc(f.category)} | "
                f"Confidence {_esc(f.confidence.value)} | Source {source}",
                st["small"],
            )
            block: list[Flowable] = [
                Paragraph("What this means", st["label"]),
                Paragraph(_esc(f.explanation), st["body"]),
            ]
            story.append(KeepTogether([CondPageBreak(40 * mm), heading, meta, *block]))
            story += [
                Paragraph("Why this severity", st["label"]),
                Paragraph(_esc(f.severity_rationale), st["body"]),
                Paragraph("How to fix", st["label"]),
                Paragraph(_esc(f.remediation), st["body"]),
            ]
            if f.evidence:
                story.append(Paragraph("Evidence", st["label"]))
                story += [
                    Paragraph(f"<b>{_esc(key, 80)}</b>: {_esc(value)}", st["small"])
                    for key, value in evidence_lines(f.evidence)
                ]
            if f.references:
                story.append(Paragraph("References", st["label"]))
                story += [Paragraph(_esc(ref, 500), st["small"]) for ref in f.references]
            story.append(Spacer(1, 6 * mm))
        return story

    def _appendix(self, doc: ReportDocument, st: dict[str, ParagraphStyle]) -> list[Flowable]:
        if not doc.raw:
            return []
        story: list[Flowable] = [
            PageBreak(),
            Paragraph("Appendix: raw data", st["h1"]),
            Paragraph(
                "Raw tool output for advanced readers, truncated to keep the report readable. "
                "The JSON export contains the complete data.",
                st["small"],
            ),
        ]
        budget = RAW_TOTAL_MAX_CHARS
        for section in doc.raw:
            story.append(Paragraph(f"{_esc(section.label, 200)} (run {section.run_id})", st["h2"]))
            if budget <= 0:
                story.append(Paragraph("Omitted: appendix size limit reached.", st["small"]))
                continue
            text, cut = raw_json(section.data, min(budget, RAW_SECTION_MAX_CHARS))
            budget -= len(text)
            # Preformatted: no markup parsing at all, so raw data is inert text.
            story.append(Preformatted(text, st["mono"], maxLineLength=110))
            if cut:
                story.append(Paragraph("[Truncated]", st["small"]))
        return story
