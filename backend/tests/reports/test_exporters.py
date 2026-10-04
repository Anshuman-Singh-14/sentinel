"""Exporter plugins: registry, PDF safety, CSV injection, JSON and text output."""

import json
import re
from datetime import UTC, datetime

import pytest

from app.db.models.report import REPORT_FORMATS
from app.engine.schemas import Severity
from app.reports.document import ReportDocument
from app.reports.exporters import Exporter, clean_text, exporters, get_exporter
from app.reports.exporters._format import compact_json, raw_json
from app.reports.exporters.base import register
from app.reports.exporters.pdf import _esc
from app.reports.naming import report_filename, slug
from tests.reports.factories import document, finding

HOSTILE_MARKUP = (
    '<a href="javascript:alert(1)">click</a> <img src="file:///etc/passwd"/> '
    '<link href="https://evil.example/"> <font size="40">big</font> &amp; <b>'
)

# --- registry -------------------------------------------------------------------------


def test_registry_matches_the_database_constraint() -> None:
    assert sorted(e.format for e in exporters()) == sorted(REPORT_FORMATS)
    for exporter in exporters():
        assert exporter.media_type and exporter.label and exporter.extension


def test_unknown_format_is_a_lookup_error() -> None:
    with pytest.raises(LookupError):
        get_exporter("docx")


@pytest.mark.parametrize("fmt", ["pdf", "PDF", "../x", "toolongformat"])
def test_registration_rejects_duplicate_or_malformed_formats(fmt: str) -> None:
    with pytest.raises(ValueError, match="exporter format"):

        @register
        class _Bad(Exporter):
            format = fmt
            label = "x"
            media_type = "text/plain"
            extension = "txt"

            def render(self, doc: ReportDocument) -> bytes:
                return b""


# --- shared text cleaning ---------------------------------------------------------------


def test_clean_text_removes_control_characters_but_keeps_layout() -> None:
    assert clean_text("a\x00b\x1bc\x7fd\r\ne\tf") == "abcd\ne\tf"
    assert clean_text(None) == ""


# --- PDF -----------------------------------------------------------------------------------


def test_esc_neutralises_paragraph_markup() -> None:
    escaped = _esc(HOSTILE_MARKUP)
    assert "<" not in escaped.replace("<br/>", "") and ">" not in escaped.replace("<br/>", "")
    assert "&lt;a href=" in escaped and "&amp;amp;" in escaped
    assert _esc("line1\nline2") == "line1<br/>line2"


def test_pdf_never_turns_tool_output_into_links_or_actions() -> None:
    hostile = finding(
        HOSTILE_MARKUP,
        Severity.CRITICAL,
        explanation=HOSTILE_MARKUP,
        remediation=HOSTILE_MARKUP,
        evidence={"banner": HOSTILE_MARKUP},
        references=["javascript:alert(1)", "https://evil.example/"],
    )
    data = get_exporter("pdf").render(
        document([hostile], target=HOSTILE_MARKUP, raw={"html": HOSTILE_MARKUP})
    )
    assert data.startswith(b"%PDF-")
    # No link annotations, URI or JavaScript actions, launches or embedded files.
    for marker in (b"/Annot", b"/URI", b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile"):
        assert marker not in data, marker


def test_pdf_renders_edge_cases() -> None:
    pdf = get_exporter("pdf")
    # No findings at all.
    assert pdf.render(document([])).startswith(b"%PDF-")
    # Unicode, control characters and very long unbroken tokens.
    odd = finding(
        "café — 日本語 \U0001f600 \x00\x1b nul" + "A" * 250,
        Severity.LOW,
        evidence={"k": "x" * 5000, "nested": {"a": [1, 2, 3]}},
    )
    assert pdf.render(document([odd])).startswith(b"%PDF-")
    # Many findings and a huge raw section (appendix is truncated, not exploded).
    many = [finding(f"Finding {i}", Severity.MEDIUM) for i in range(150)]
    big = pdf.render(document(many, raw={"blob": "y" * 500_000, "ports": list(range(5000))}))
    assert big.startswith(b"%PDF-") and len(big) < 5_000_000


def test_pdf_page_count_is_consistent() -> None:
    data = get_exporter("pdf").render(document())
    pages = len(re.findall(rb"/Type /Page\b", data))
    assert pages >= 4  # cover, summary, findings table, details (+ appendix)


# --- JSON and text -------------------------------------------------------------------------


def test_json_export_round_trips_to_the_same_document() -> None:
    doc = document()
    parsed = ReportDocument.model_validate_json(get_exporter("json").render(doc))
    assert parsed == doc


def test_text_export_contains_the_essentials() -> None:
    doc = document(errors=["Threat intel: not installed"], raw={"blob": "z" * 100_000})
    text = get_exporter("txt").render(doc).decode()
    assert doc.risk.headline in text
    assert "F-01 [HIGH] Self-signed certificate" in text
    assert "Threat intel: not installed" in text
    assert "[truncated; the JSON export has the full raw data]" in text
    assert all(len(line) <= 120 for line in text.splitlines() if "z" not in line)


def test_compact_json_is_valid_and_compact() -> None:
    data = {"ports": list(range(300)), "open": [{"port": 80, "banner": "x" * 150}], "e": {}}
    text = compact_json(data)
    assert json.loads(text) == data
    assert len(text.splitlines()) < 30


def test_raw_json_reports_truncation() -> None:
    text, cut = raw_json({"blob": "x" * 1000}, limit=100)
    assert cut and len(text) == 100
    assert raw_json({"a": 1})[1] is False


# --- filenames ---------------------------------------------------------------------------


def test_filenames_are_ascii_slugs() -> None:
    name = report_filename(
        kind="playbook_run",
        name="Web Defensive Audit",
        target='evil"; filename=x.exe\r\n../../été.example',
        created_at=datetime(2026, 10, 4, 12, 30, 5, tzinfo=UTC),
        extension="pdf",
    )
    assert re.fullmatch(r"[A-Za-z0-9._-]+", name)
    assert name.startswith("sentinel-playbook-Web-Defensive-Audit-evil-filename-x.exe")
    assert name.endswith("-20261004-123005.pdf") and len(name) <= 160


def test_slug_handles_empty_and_hostile_input() -> None:
    assert slug(None) == "" and slug("../..") == "" and slug("a" * 99) == "a" * 40
