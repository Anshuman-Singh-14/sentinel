"""Parser plugins. Adding a format = one module here plus one entry in PARSERS."""

from collections.abc import Callable, Iterable
from datetime import datetime

from app.tools.log_analyzer.parsers.auth_log import AuthLogParser
from app.tools.log_analyzer.parsers.base import LogEvent, LogParser, ParseResult
from app.tools.log_analyzer.parsers.nginx_access import NginxAccessParser

PARSERS: dict[str, Callable[[datetime], LogParser]] = {
    "auth_log": lambda reference: AuthLogParser(reference),
    "nginx_access": lambda reference: NginxAccessParser(),
}
PARSER_NAMES = tuple(PARSERS)
# Auto-detection looks at this many non-empty lines and picks the parser that
# produces the most events (recognised lines break ties).
DETECT_SAMPLE_LINES = 200


def build(name: str, reference: datetime) -> LogParser:
    return PARSERS[name](reference)


def detect(sample: Iterable[str], reference: datetime) -> str | None:
    """Pick the parser that understands the sample best, or None if none does."""
    lines = [line for line in sample if line.strip()][:DETECT_SAMPLE_LINES]
    best: tuple[int, int, str] | None = None
    for name in PARSER_NAMES:
        parser = build(name, reference)
        events = recognised = 0
        for number, line in enumerate(lines, 1):
            result = parser.parse(line, number)
            recognised += result.recognised
            events += result.event is not None
        score = (events, recognised, name)
        if recognised and (best is None or score[:2] > best[:2]):
            best = score
    return best[2] if best else None


__all__ = ["PARSERS", "PARSER_NAMES", "LogEvent", "LogParser", "ParseResult", "build", "detect"]
