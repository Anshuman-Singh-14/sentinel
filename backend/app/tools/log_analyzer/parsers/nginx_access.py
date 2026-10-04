"""nginx (and Apache) access logs in the standard *combined* format.

    203.0.113.9 - - [04/Oct/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.5"

nginx escapes double quotes inside fields as ``\\x22``, so ``[^"]*`` cannot be
fooled into splitting a field by a crafted user agent. A malformed request
line (binary TLS bytes sent to a plain-HTTP port, an empty request) is kept as
an event with the raw request text: scanners produce exactly those.
"""

import re
from datetime import datetime
from typing import ClassVar

from app.tools.log_analyzer.parsers.base import (
    UNRECOGNISED,
    LogEvent,
    LogParser,
    ParseResult,
    clean_ip,
)

COMBINED = (
    r"^(?P<ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
REQUEST = r"^(?P<method>[A-Z]{1,16}) (?P<target>\S+)(?: (?P<protocol>HTTP/[\d.]+))?$"

_COMBINED = re.compile(COMBINED)
_REQUEST = re.compile(REQUEST)


class NginxAccessParser(LogParser):
    name = "nginx_access"
    title = "nginx / Apache access log (combined format)"
    format = (
        '\'203.0.113.9 - - [04/Oct/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" '
        "\"Mozilla/5.0\"' (the default 'combined' log_format)"
    )
    patterns: ClassVar[dict[str, str]] = {"combined": COMBINED, "request": REQUEST}

    def parse(self, line: str, line_no: int) -> ParseResult:
        match = _COMBINED.match(line)
        if not match:
            return UNRECOGNISED
        try:
            timestamp: datetime | None = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            timestamp = None
        request = match["request"]
        parts = _REQUEST.match(request)
        fields = {
            "method": parts["method"] if parts else "",
            "target": parts["target"] if parts else request,
            "request": request,
            "status": match["status"],
            "user_agent": match["ua"],
            "referer": match["referer"],
        }
        return ParseResult(
            True,
            LogEvent(
                kind="http_request",
                timestamp=timestamp,
                ip=clean_ip(match["ip"]),
                fields=fields,
                line_no=line_no,
            ),
        )
