"""Phase 10 acceptance (05-phases.md):

* the sample auth.log and nginx logs in tests/fixtures yield the expected detections;
* traversal attempts are refused (see also tests/security/test_path_guard.py);
* a large file is processed within memory bounds.
"""

import gzip
import io
import tracemalloc
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import structlog

from app.config import get_settings
from app.engine.base_tool import RunCancelled, ToolContext
from app.engine.runner import execute_tool
from app.engine.schemas import Finding, RunStatus
from app.tools.log_analyzer import service, translator
from app.tools.log_analyzer.rules import get_rules
from app.tools.log_analyzer.schemas import LogAnalyzerParams
from app.tools.log_analyzer.tool import LogAnalyzerTool

FIXTURES = Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "logs"
REF = datetime(2026, 10, 5, tzinfo=UTC)


def ctx() -> ToolContext:
    return ToolContext(run_id=uuid.uuid4(), logger=structlog.get_logger())


async def analyse_bytes(data: bytes, parser: str = "auto", **limits: Any) -> dict[str, Any]:
    options = {"max_lines": 1_000_000, "max_line_bytes": 8192, "max_total_bytes": 10**9} | limits
    return await service.analyse(
        io.BufferedReader(io.BytesIO(data)),
        size=len(data),
        parser_choice=parser,
        rules=get_rules(),
        ctx=ctx(),
        reference=REF,
        **options,
    )


async def analyse_fixture(name: str) -> dict[str, Any]:
    return await analyse_bytes((FIXTURES / name).read_bytes())


def detections(raw: dict[str, Any]) -> set[tuple[str, str]]:
    return {(d["rule_id"], d["key"]) for d in raw["detections"]}


def by_item(findings: list[Finding], prefix: str) -> Finding:
    return next(f for f in findings if f.item.startswith(prefix))


async def test_auth_log_fixture_yields_the_expected_detections() -> None:
    raw = await analyse_fixture("auth.log")

    assert raw["parser"]["name"] == "auth_log"
    assert detections(raw) == {
        ("ssh_bruteforce", "203.0.113.50"),
        ("invalid_user_enumeration", "198.51.100.23"),
        ("success_after_failures", "203.0.113.77"),
        ("root_login_attempt", "203.0.113.50"),
        ("root_login_attempt", "192.0.2.99"),
    }
    assert raw["stats"]["unrecognised"] == 2  # the rotation marker and the kernel line
    assert raw["stats"]["events_by_kind"] == {
        "ssh_accepted": 3,
        "ssh_failed": 21,
        "ssh_invalid_user": 5,
    }


async def test_auth_log_findings_severity_and_rationale() -> None:
    findings = translator.translate(await analyse_fixture("auth.log"))

    assert [f.severity.value for f in findings] == [
        "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "INFO",
    ]  # fmt: skip
    brute = by_item(findings, "SSH password guessing from 203.0.113.50")
    assert brute.evidence["count"] == 12 and brute.evidence["peak_in_window"] == "12"
    assert brute.evidence["first_seen"].startswith("2026-10-04T09:15:00")
    assert "5 or more failed logins" in brute.severity_rationale
    assert "fail2ban" in brute.remediation
    root_ok = by_item(findings, "Successful SSH login as root from 192.0.2.99")
    assert root_ok.severity.value == "HIGH" and "escalated to HIGH" in root_ok.severity_rationale
    root_failed = by_item(findings, "SSH login attempts as root from 203.0.113.50")
    assert root_failed.severity.value == "MEDIUM"
    success = by_item(findings, "Successful SSH login from 203.0.113.77 after 4 failed")
    assert success.confidence.value == "MEDIUM"
    summary = findings[-1]
    assert summary.category == "LOG_SUMMARY" and summary.item.startswith("37 lines analysed")


async def test_nginx_fixture_yields_the_expected_detections() -> None:
    raw = await analyse_fixture("nginx_access.log")

    assert raw["parser"]["name"] == "nginx_access"
    assert detections(raw) == {
        ("path_traversal", "198.51.100.66"),
        ("path_traversal", "203.0.113.90"),
        ("scanner_user_agent", "192.0.2.200"),
        ("scanner_user_agent", "192.0.2.201"),
        ("high_request_rate", "203.0.113.120"),
        ("error_spike", "2026-10-04T12:20:00+00:00"),
        ("error_spike", "2026-10-04T12:30:00+00:00"),
    }


async def test_nginx_findings_escalate_where_the_attack_may_have_worked() -> None:
    findings = translator.translate(await analyse_fixture("nginx_access.log"))

    leaked = by_item(findings, "Path traversal from 203.0.113.90 answered with success")
    assert leaked.severity.value == "HIGH" and findings[0] == leaked
    rejected = by_item(findings, "Path traversal attempts from 198.51.100.66")
    assert rejected.severity.value == "MEDIUM"
    assert "overlong" in rejected.explanation and "after 2 decode" in rejected.explanation
    outage = by_item(findings, "Spike of 60 error responses")
    assert outage.severity.value == "MEDIUM" and "mostly server errors" in outage.item
    probing = by_item(findings, "Spike of 150 error responses")
    assert probing.severity.value == "LOW"
    assert by_item(findings, "Vulnerability scanner at work from 192.0.2.201").evidence[
        "matched"
    ] == ["sqlmap"]


async def test_findings_never_carry_raw_control_characters() -> None:
    line = (
        '192.0.2.5 - - [04/Oct/2026:12:00:01 +0000] "GET /../\x1b[2Jetc/passwd HTTP/1.1" '
        '404 1 "-" "x"\n'
    )
    findings = translator.translate(await analyse_bytes(line.encode()))
    traversal = by_item(findings, "Path traversal attempts from 192.0.2.5")
    assert "\x1b" not in str(traversal.evidence) and "\x1b" not in traversal.explanation


async def test_gzip_input_and_explicit_parser() -> None:
    data = gzip.compress((FIXTURES / "auth.log").read_bytes())
    raw = await analyse_bytes(data, parser="auth_log")
    assert raw["stats"]["compressed"] and ("ssh_bruteforce", "203.0.113.50") in detections(raw)


async def test_wrong_explicit_parser_gives_a_format_note() -> None:
    raw = await analyse_bytes((FIXTURES / "auth.log").read_bytes(), parser="nginx_access")
    findings = translator.translate(raw)
    assert raw["detections"] == []
    assert any(f.category == "LOG_FORMAT" for f in findings)
    assert findings[-1].item.startswith("No suspicious patterns")


async def test_unknown_format_is_a_clear_error() -> None:
    with pytest.raises(service.UnsupportedLog, match="Supported formats"):
        await analyse_bytes(b"just some text\nnothing to see\n")


async def test_line_limit_becomes_a_partial_result_error() -> None:
    context = ctx()
    await service.analyse(
        io.BufferedReader(io.BytesIO((FIXTURES / "nginx_access.log").read_bytes())),
        size=None,
        parser_choice="nginx_access",
        rules=get_rules(),
        ctx=context,
        max_lines=50,
        max_line_bytes=8192,
        max_total_bytes=10**9,
    )
    assert [e.code for e in context.errors] == ["log_truncated"]


def big_log(lines: int) -> bytes:
    start = datetime(2026, 10, 4, tzinfo=UTC)
    rows = []
    for i in range(lines):
        stamp = (start + timedelta(seconds=i)).strftime("%d/%b/%Y:%H:%M:%S")
        rows.append(
            f'192.0.2.{i % 50} - - [{stamp} +0000] "GET /page/{i} HTTP/1.1" 200 512 "-" '
            f'"Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"\n'
        )
    return "".join(rows).encode()


async def peak_memory(data: bytes, tmp_path: Path) -> int:
    path = tmp_path / "big.log"
    path.write_bytes(data)
    tracemalloc.start()
    try:
        with path.open("rb") as handle:
            await service.analyse(
                handle,
                size=len(data),
                parser_choice="nginx_access",
                rules=get_rules(),
                ctx=ctx(),
                max_lines=10_000_000,
                max_line_bytes=8192,
                max_total_bytes=10**10,
            )
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


async def test_large_file_is_processed_within_memory_bounds(tmp_path: Path) -> None:
    small = big_log(10_000)
    large = big_log(100_000)  # ~13 MB
    small_peak = await peak_memory(small, tmp_path)
    large_peak = await peak_memory(large, tmp_path)

    # Streaming: ten times the input does not mean ten times the memory, and
    # the peak stays far below the file size.
    assert large_peak < small_peak * 2 + 1_000_000
    assert large_peak < len(large) / 4


async def test_cancellation_is_checked_while_reading() -> None:
    context = ctx()

    async def cancelled() -> bool:
        return True

    context.cancel_check = cancelled
    with pytest.raises(RunCancelled):
        await service.analyse(
            io.BufferedReader(io.BytesIO(big_log(service.YIELD_EVERY + 10))),
            size=None,
            parser_choice="nginx_access",
            rules=get_rules(),
            ctx=context,
            max_lines=10**6,
            max_line_bytes=8192,
            max_total_bytes=10**9,
        )


# --- the tool, through the framework runner ------------------------------------------


@pytest.fixture
def log_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "logs"
    root.mkdir()
    (root / "auth.log").write_bytes((FIXTURES / "auth.log").read_bytes())
    monkeypatch.setenv("LOG_ROOT", str(root))
    get_settings.cache_clear()
    yield root
    monkeypatch.undo()
    get_settings.cache_clear()


async def run_tool(params: dict[str, Any], upload: Path | None = None) -> Any:
    context = ctx()
    context.upload_path = upload
    return await execute_tool(
        LogAnalyzerTool(), params, run_id=context.run_id, initiated_by="t", ctx=context
    )


async def test_tool_reads_from_log_root(log_root: Path) -> None:
    result = await run_tool({"path": "auth.log"})
    assert result.status is RunStatus.COMPLETED and result.target == "auth.log"
    size = (FIXTURES / "auth.log").stat().st_size
    assert result.raw_data["source"] == {"kind": "log_root", "name": "auth.log", "bytes": size}
    assert result.summary.by_severity["HIGH"] == 2


async def test_tool_reads_an_upload(tmp_path: Path) -> None:
    upload = tmp_path / "x.upload"
    upload.write_bytes((FIXTURES / "nginx_access.log").read_bytes())
    result = await run_tool({"upload_name": "access.log"}, upload)
    assert result.status is RunStatus.COMPLETED and result.target == "access.log"
    assert result.raw_data["source"]["kind"] == "upload"


async def test_missing_upload_is_a_structured_failure() -> None:
    result = await run_tool({"upload_name": "gone.log"}, None)
    assert result.status is RunStatus.FAILED
    assert result.errors[0].code == "not_found"


async def test_traversal_through_params_is_refused(log_root: Path) -> None:
    (log_root.parent / "secret.txt").write_text("top secret", encoding="utf-8")
    for path in ["../secret.txt", "/etc/passwd", "a/../../secret.txt"]:
        result = await run_tool({"path": path})
        assert result.status is RunStatus.FAILED and result.errors[0].code == "invalid_params"
    missing = await run_tool({"path": "nope.log"})
    assert missing.status is RunStatus.FAILED and missing.errors[0].code == "not_found"


async def test_symlink_escape_is_refused(log_root: Path) -> None:
    secret = log_root.parent / "secret.log"
    secret.write_bytes((FIXTURES / "auth.log").read_bytes())
    try:
        (log_root / "link.log").symlink_to(secret)
    except OSError:  # pragma: no cover - no symlink support (e.g. Windows without privilege)
        pytest.skip("symlinks unavailable")
    result = await run_tool({"path": "link.log"})
    assert result.status is RunStatus.FAILED and result.errors[0].code == "path_rejected"


async def test_log_root_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_ROOT", "")
    get_settings.cache_clear()
    try:
        result = await run_tool({"path": "auth.log"})
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
    assert result.status is RunStatus.FAILED and "disabled" in result.errors[0].message


@pytest.mark.parametrize(
    "params",
    [
        {},  # no source
        {"path": "a.log", "upload_name": "b.log"},  # both
        {"path": "a\x00.log"},
        {"path": "C:/windows/win.ini"},
        {"path": "a\\..\\b"},
        {"path": "x", "parser": "apache_error"},
        {"path": "x", "extra": 1},
    ],
)
def test_params_validation(params: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        LogAnalyzerParams.model_validate(params)


def test_params_schema_hides_upload_name_from_the_form() -> None:
    schema = LogAnalyzerParams.model_json_schema()
    assert schema["properties"]["upload_name"]["readOnly"] is True
    assert schema["properties"]["parser"]["enum"] == ["auto", "auth_log", "nginx_access"]
    assert LogAnalyzerTool.accepts_upload and LogAnalyzerTool.max_upload_bytes() > 0
