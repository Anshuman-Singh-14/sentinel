"""The parser plugin contract.

A parser turns one log line into zero or one ``LogEvent``. It declares its
format and the regular expressions it uses, so the UI and the raw output can
show exactly what was matched. Lines it does not recognise are counted by the
caller, never fatal: real logs mix many programs and formats.

Every regex here is anchored and free of nested quantifiers, and the reader
caps line length, so matching time stays linear in the line length (no
catastrophic backtracking on hostile input).
"""

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar


@dataclass(slots=True)
class LogEvent:
    """One security-relevant event extracted from a line."""

    kind: str  # e.g. ssh_failed, ssh_accepted, http_request
    timestamp: datetime | None
    ip: str | None
    fields: dict[str, str] = field(default_factory=dict)
    line_no: int = 0


class ParseResult:
    """What a parser made of a line: a recognised line may still carry no event."""

    __slots__ = ("event", "recognised")

    def __init__(self, recognised: bool, event: LogEvent | None = None) -> None:
        self.recognised = recognised
        self.event = event


UNRECOGNISED = ParseResult(False)
IGNORED = ParseResult(True)  # well-formed, but nothing security-relevant


class LogParser(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    format: ClassVar[str]  # human description of the expected format
    patterns: ClassVar[dict[str, str]]  # name -> regex source, for transparency

    @abstractmethod
    def parse(self, line: str, line_no: int) -> ParseResult:
        """Parse one line (already decoded, no trailing newline)."""

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "title": self.title,
            "format": self.format,
            "patterns": self.patterns,
        }


def clean_ip(value: str | None) -> str | None:
    """A valid IP address in canonical form, or None (logs can hold anything)."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None
