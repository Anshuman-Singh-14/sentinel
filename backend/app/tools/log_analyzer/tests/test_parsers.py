from datetime import UTC, datetime

import pytest

from app.tools.log_analyzer import parsers
from app.tools.log_analyzer.parsers.auth_log import AuthLogParser
from app.tools.log_analyzer.parsers.nginx_access import NginxAccessParser

REF = datetime(2026, 10, 5, tzinfo=UTC)


def auth(line: str, reference: datetime = REF) -> parsers.ParseResult:
    return AuthLogParser(reference).parse(line, 7)


def test_failed_password_classic_syslog() -> None:
    result = auth(
        "Oct  4 09:15:00 web01 sshd[3000]: Failed password for root from 203.0.113.50 "
        "port 40000 ssh2"
    )
    assert result.recognised and result.event is not None
    event = result.event
    assert event.kind == "ssh_failed" and event.ip == "203.0.113.50" and event.line_no == 7
    assert event.fields == {"user": "root", "invalid_user": "no", "method": "password"}
    assert event.timestamp == datetime(2026, 10, 4, 9, 15, tzinfo=UTC)


def test_failed_for_invalid_user_and_invalid_user_lines() -> None:
    failed = auth(
        "Oct  4 10:00:02 h sshd[1]: Failed password for invalid user oracle from 198.51.100.23 "
        "port 51000 ssh2"
    ).event
    invalid = auth(
        "Oct  4 10:00:00 h sshd[1]: Invalid user oracle from 198.51.100.23 port 51000"
    ).event
    assert failed is not None and failed.fields["invalid_user"] == "yes"
    assert invalid is not None and invalid.kind == "ssh_invalid_user"
    assert invalid.fields["user"] == "oracle"


def test_empty_invalid_user_name_is_kept_visible() -> None:
    event = auth("Oct  4 10:00:00 h sshd[1]: Invalid user  from 198.51.100.23 port 1").event
    assert event is not None and event.fields["user"] == "(empty)"


def test_accepted_rfc3339_and_sshd_session() -> None:
    event = auth(
        "2026-10-04T12:05:00.123456+02:00 h sshd-session[6000]: Accepted publickey for alice "
        "from 2001:db8::1 port 53000 ssh2: ED25519 SHA256:x"
    ).event
    assert event is not None and event.kind == "ssh_accepted"
    assert event.ip == "2001:db8::1" and event.fields["method"] == "publickey"
    assert event.timestamp is not None and event.timestamp.utcoffset() is not None


def test_year_rollover() -> None:
    # Read on 2 January 2027, "Dec 31" belongs to 2026.
    event = auth(
        "Dec 31 23:59:00 h sshd[1]: Failed password for x from 192.0.2.1 port 1 ssh2",
        datetime(2027, 1, 2, tzinfo=UTC),
    ).event
    assert event is not None and event.timestamp is not None and event.timestamp.year == 2026


def test_other_programs_are_recognised_but_ignored() -> None:
    result = auth("Oct  4 08:01:00 h CRON[2001]: pam_unix(cron:session): session opened")
    assert result.recognised and result.event is None
    other = auth("Oct  4 08:01:00 h sshd[1]: Connection closed by 192.0.2.1 port 22 [preauth]")
    assert other.recognised and other.event is None


@pytest.mark.parametrize("line", ["", "--- rotated ---", "x" * 9000, "Oct 99 99:99:99"])
def test_garbage_is_unrecognised(line: str) -> None:
    assert not auth(line).recognised


def test_invalid_ip_becomes_none() -> None:
    event = auth(
        "Oct  4 09:00:00 h sshd[1]: Failed password for x from not-an-ip port 1 ssh2"
    ).event
    assert event is not None and event.ip is None


def test_nginx_combined() -> None:
    line = (
        '203.0.113.9 - bob [04/Oct/2026:12:00:01 +0000] "GET /a?b=1 HTTP/1.1" 404 153 '
        '"https://ref.example/" "Mozilla/5.0 (Nikto/2.5.0)"'
    )
    event = NginxAccessParser().parse(line, 3).event
    assert event is not None and event.kind == "http_request" and event.ip == "203.0.113.9"
    assert event.fields["method"] == "GET" and event.fields["target"] == "/a?b=1"
    assert event.fields["status"] == "404" and "Nikto" in event.fields["user_agent"]
    assert event.timestamp == datetime(2026, 10, 4, 12, 0, 1, tzinfo=UTC)


def test_nginx_malformed_request_line_is_kept() -> None:
    line = r'192.0.2.1 - - [04/Oct/2026:12:00:01 +0000] "\x16\x03\x01" 400 157 "-" "-"'
    event = NginxAccessParser().parse(line, 1).event
    assert event is not None and event.fields["method"] == ""
    assert event.fields["target"] == r"\x16\x03\x01"


def test_nginx_rejects_non_combined() -> None:
    assert not NginxAccessParser().parse("Oct  4 09:00:00 h sshd[1]: hi", 1).recognised


def test_detect_picks_the_right_parser() -> None:
    ssh = ["Oct  4 09:15:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"]
    web = ['192.0.2.1 - - [04/Oct/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"']
    assert parsers.detect(ssh, REF) == "auth_log"
    assert parsers.detect(web, REF) == "nginx_access"
    assert parsers.detect(["hello", "world"], REF) is None
    assert parsers.detect([], REF) is None


def test_parsers_describe_their_patterns() -> None:
    for name in parsers.PARSER_NAMES:
        description = parsers.build(name, REF).describe()
        assert description["name"] == name and description["patterns"]
