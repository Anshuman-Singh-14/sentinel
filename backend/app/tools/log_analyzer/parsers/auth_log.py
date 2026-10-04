"""OpenSSH authentication events from a syslog ``auth.log`` (or ``secure``).

Two line prefixes are understood:

* classic syslog: ``Oct  4 12:00:01 host sshd[123]: <message>``. It has no
  year, so the year is inferred from a reference time: a date that would lie
  in the future is taken to be from the previous year (logs that span New Year).
* RFC 3339 (modern rsyslog, journald exports):
  ``2026-10-04T12:00:01.123456+00:00 host sshd[123]: <message>``.

Only messages from ``sshd`` (and ``sshd-session``, OpenSSH 9.8+) produce events.
Other well-formed syslog lines (cron, sudo, systemd...) are recognised and
ignored; anything else is counted as unrecognised.
"""

import re
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from app.tools.log_analyzer.parsers.base import (
    IGNORED,
    UNRECOGNISED,
    LogEvent,
    LogParser,
    ParseResult,
    clean_ip,
)

SYSLOG_PREFIX = (
    r"^(?P<ts>[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
ISO_PREFIX = (
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
FAILED = (
    r"^Failed (?P<method>password|publickey|none|keyboard-interactive/pam|hostbased) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+"
)
INVALID_USER = r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port \d+)?"
ACCEPTED = r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"

_SYSLOG = re.compile(SYSLOG_PREFIX)
_ISO = re.compile(ISO_PREFIX)
_FAILED = re.compile(FAILED)
_INVALID = re.compile(INVALID_USER)
_ACCEPTED = re.compile(ACCEPTED)
SSH_PROGRAMS = frozenset({"sshd", "sshd-session"})


def _syslog_time(text: str, reference: datetime) -> datetime | None:
    try:
        parsed = datetime.strptime(f"{reference.year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    stamp = parsed.replace(tzinfo=UTC)
    if stamp > reference + timedelta(days=2):
        # "Dec 31" read in January belongs to last year.
        stamp = stamp.replace(year=reference.year - 1)
    return stamp


def _iso_time(text: str) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


class AuthLogParser(LogParser):
    name = "auth_log"
    title = "SSH authentication log (OpenSSH, syslog)"
    format = (
        "syslog lines such as 'Oct  4 12:00:01 host sshd[123]: Failed password for root "
        "from 203.0.113.5 port 52811 ssh2' (classic or RFC 3339 timestamps)"
    )
    patterns: ClassVar[dict[str, str]] = {
        "syslog_prefix": SYSLOG_PREFIX,
        "iso_prefix": ISO_PREFIX,
        "failed": FAILED,
        "invalid_user": INVALID_USER,
        "accepted": ACCEPTED,
    }

    def __init__(self, reference: datetime | None = None) -> None:
        self.reference = reference or datetime.now(UTC)

    def parse(self, line: str, line_no: int) -> ParseResult:
        match = _SYSLOG.match(line)
        if match:
            timestamp = _syslog_time(match["ts"], self.reference)
        else:
            match = _ISO.match(line)
            if not match:
                return UNRECOGNISED
            timestamp = _iso_time(match["ts"])
        if match["prog"] not in SSH_PROGRAMS:
            return IGNORED
        message = match["msg"]
        if found := _FAILED.match(message):
            return self._event(
                "ssh_failed",
                found,
                timestamp,
                line_no,
                invalid_user="yes" if found["invalid"] else "no",
            )
        if found := _INVALID.match(message):
            return self._event("ssh_invalid_user", found, timestamp, line_no)
        if found := _ACCEPTED.match(message):
            return self._event("ssh_accepted", found, timestamp, line_no)
        return IGNORED

    @staticmethod
    def _event(
        kind: str, found: re.Match[str], timestamp: datetime | None, line_no: int, **extra: str
    ) -> ParseResult:
        fields = {"user": found["user"] or "(empty)", **extra}
        if "method" in found.groupdict():
            fields["method"] = found["method"]
        return ParseResult(
            True,
            LogEvent(
                kind=kind,
                timestamp=timestamp,
                ip=clean_ip(found["ip"]),
                fields=fields,
                line_no=line_no,
            ),
        )
