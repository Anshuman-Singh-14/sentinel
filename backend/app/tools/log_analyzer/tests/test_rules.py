from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.tools.log_analyzer import rules as rules_module
from app.tools.log_analyzer.parsers import LogEvent
from app.tools.log_analyzer.rules import (
    BurstDetector,
    DistinctDetector,
    MatchDetector,
    Rule,
    RuleError,
    SequenceDetector,
    SpikeDetector,
    get_rules,
    load_rules,
    looks_like_traversal,
    sample_text,
)

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def rule(rule_id: str) -> Rule:
    return next(r for r in get_rules().rules if r.id == rule_id)


def ev(kind: str, ip: str | None = "192.0.2.1", seconds: float = 0, **fields: str) -> LogEvent:
    return LogEvent(kind=kind, timestamp=T0 + timedelta(seconds=seconds), ip=ip, fields=fields)


def test_shipped_rules_load_and_cover_the_spec() -> None:
    shipped = {r.id for r in get_rules().rules}
    assert shipped == {
        "ssh_bruteforce",
        "invalid_user_enumeration",
        "success_after_failures",
        "root_login_attempt",
        "path_traversal",
        "scanner_user_agent",
        "high_request_rate",
        "error_spike",
    }


def test_every_rule_has_a_knowledge_entry() -> None:
    from app.engine.knowledge import get_knowledge_base

    kb = get_knowledge_base()
    for item in get_rules().rules:
        assert item.knowledge in kb


@pytest.mark.parametrize(
    "body",
    [
        "rules: [}",  # not YAML
        "schema_version: 1\nversion: '1.0.0'\nrules:\n  - id: x\n",  # incomplete
        "!!python/object/apply:os.system ['echo pwned']",  # safe_load refuses tags
        (
            "schema_version: 1\nversion: '1.0.0'\nrules:\n"
            "  - {id: ab, title: t, parser: auth_log, detector: burst, events: [x],"
            " threshold: 1, category: X, knowledge: log_analyzer.x}\n"
        ),  # burst without window_seconds
        (
            "schema_version: 1\nversion: '1.0.0'\nrules:\n"
            "  - {id: ab, title: t, parser: nope, detector: match, events: [x], field: f,"
            " equals: [y], threshold: 1, category: X, knowledge: log_analyzer.x}\n"
        ),  # unknown parser
    ],
)
def test_bad_rule_files_are_rejected(tmp_path: Path, body: str) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(RuleError):
        load_rules(path)


def test_oversized_rule_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("x" * 100, encoding="utf-8")
    monkeypatch.setattr(rules_module, "MAX_RULES_FILE_BYTES", 10)
    with pytest.raises(RuleError, match="exceeds"):
        load_rules(path)


def test_burst_needs_threshold_within_window() -> None:
    slow = BurstDetector(rule("ssh_bruteforce"))
    for i in range(10):
        slow.feed(ev("ssh_failed", seconds=i * 20, user="root"))  # 3 per minute
    assert slow.results() == []

    fast = BurstDetector(rule("ssh_bruteforce"))
    for i in range(6):
        fast.feed(ev("ssh_failed", seconds=i * 5, user="root" if i % 2 else "admin"))
    (hit,) = fast.results()
    assert hit.key == "192.0.2.1" and hit.count == 6
    assert hit.details["peak_in_window"] == "6" and hit.details["users"] == ["admin", "root"]


def test_burst_ignores_events_without_ip_or_time() -> None:
    detector = BurstDetector(rule("ssh_bruteforce"))
    for _ in range(10):
        detector.feed(ev("ssh_failed", ip=None))
        detector.feed(LogEvent("ssh_failed", None, "192.0.2.9"))
    assert detector.results() == []


def test_key_cap_marks_results_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules_module, "MAX_KEYS", 3)
    detector = DistinctDetector(rule("invalid_user_enumeration"))
    for i in range(10):
        detector.feed(ev("ssh_invalid_user", ip=f"192.0.2.{i}", user="x"))
    assert len(detector.keys) == 3 and detector.overflow


def test_distinct_counts_different_names_only() -> None:
    detector = DistinctDetector(rule("invalid_user_enumeration"))
    for name in ["a", "a", "b", "b"]:
        detector.feed(ev("ssh_invalid_user", user=name))
    assert detector.results() == []
    detector.feed(ev("ssh_invalid_user", user="c"))
    (hit,) = detector.results()
    assert hit.details["distinct_values"] == 3 and hit.details["values"] == ["a", "b", "c"]


def test_sequence_success_after_failures_and_reset() -> None:
    detector = SequenceDetector(rule("success_after_failures"))
    detector.feed(ev("ssh_failed", seconds=0))
    detector.feed(ev("ssh_failed", seconds=1))
    detector.feed(ev("ssh_accepted", seconds=2, user="bob", method="password"))
    assert detector.results() == []  # 2 failures: below the threshold, and the streak resets
    for i in range(3):
        detector.feed(ev("ssh_failed", seconds=10 + i))
    detector.feed(ev("ssh_accepted", seconds=20, user="bob", method="password"))
    (hit,) = detector.results()
    assert hit.details["successes"][0]["failures_before"] == 3


def test_sequence_respects_the_window() -> None:
    detector = SequenceDetector(rule("success_after_failures"))
    for i in range(5):
        detector.feed(ev("ssh_failed", seconds=i))
    detector.feed(ev("ssh_accepted", seconds=7200, user="bob"))  # two hours later
    assert detector.results() == []


def test_root_match_counts_failed_and_accepted() -> None:
    detector = MatchDetector(rule("root_login_attempt"))
    detector.feed(ev("ssh_failed", user="root"))
    detector.feed(ev("ssh_failed", user="alice"))
    detector.feed(ev("ssh_accepted", user="root"))
    (hit,) = detector.results()
    assert hit.count == 2 and hit.details["by_event"] == {"ssh_failed": 1, "ssh_accepted": 1}


def test_scanner_user_agent_is_case_insensitive() -> None:
    detector = MatchDetector(rule("scanner_user_agent"))
    detector.feed(ev("http_request", user_agent="Mozilla/5.0 (compatible; NUCLEI)"))
    detector.feed(ev("http_request", ip="192.0.2.2", user_agent="Mozilla/5.0 Firefox"))
    (hit,) = detector.results()
    assert hit.details["matched"] == ["nuclei"]


@pytest.mark.parametrize(
    ("target", "technique"),
    [
        ("/../../etc/passwd", "'..' sequence"),
        ("/static/..%2f..%2fetc%2fpasswd", "after 1 decode"),
        ("/f?x=%252e%252e%252fwin.ini", "after 2 decode"),
        ("/img/%c0%ae%c0%ae/etc/shadow", "overlong"),
        ("/a/..\\..\\windows", "'..' sequence"),
        ("/x/..;/admin", "'..' sequence"),
        ("/page?name=report%00.pdf", "null byte"),
        ("/view?file=/etc/passwd", "sensitive system file"),
    ],
)
def test_traversal_variants(target: str, technique: str) -> None:
    found = looks_like_traversal(target)
    assert found is not None and technique in found


@pytest.mark.parametrize("target", ["/", "/products/2026/10", "/a.b.c/d", "/...", "/q?x=%41"])
def test_traversal_no_false_positive(target: str) -> None:
    assert looks_like_traversal(target) is None


def test_traversal_records_successful_responses() -> None:
    detector = MatchDetector(rule("path_traversal"))
    detector.feed(ev("http_request", target="/../etc/passwd", status="200", request="GET x"))
    detector.feed(ev("http_request", target="/../etc/passwd", status="404", request="GET y"))
    (hit,) = detector.results()
    assert hit.details["successful_responses"] == 1 and hit.count == 2


def test_spike_buckets_and_threshold() -> None:
    detector = SpikeDetector(rule("error_spike"))
    for i in range(49):
        detector.feed(ev("http_request", seconds=i, status="404"))
    detector.feed(ev("http_request", seconds=59, status="200"))
    for i in range(60):
        detector.feed(ev("http_request", seconds=600 + i * 0.5, status="502"))
    (hit,) = detector.results()  # the first minute had 49 errors: below 50
    assert hit.count == 60 and hit.details["by_status_class"] == {"5xx": 60}


def test_sample_text_strips_control_characters_and_truncates() -> None:
    assert sample_text("a\x1b[31mred\x00\n") == "a?[31mred??"
    assert sample_text("z" * 500).endswith("…") and len(sample_text("z" * 500)) == 201
