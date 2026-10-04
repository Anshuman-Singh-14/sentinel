"""Text cleaning shared by every exporter (and the audit CSV export)."""

import re
import unicodedata

# C0/C1 control characters other than tab and newline. They have no place in
# a report, and some (NUL, form feed, escape) upset PDF and terminal viewers.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(value: object) -> str:
    """Printable, NFC-normalised text: the common first step of every exporter."""
    text = "" if value is None else str(value)
    return _CONTROL.sub("", unicodedata.normalize("NFC", text).replace("\r\n", "\n"))
