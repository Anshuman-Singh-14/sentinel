"""Phase 1 acceptance: JSON logs with request_id on every line."""

import json
import logging
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import LoggingSettings
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role
from app.core.ids import uuid7_timestamp_ms
from app.core.logging import configure_logging, get_logger
from tests.conftest import LogCapture

SYSTEM_FIELDS = {"service", "hostname", "process_user", "pid", "app_version", "environment"}
STANDARD_FIELDS = {"timestamp", "level", "event", "logger", "request_id", "user_id", "run_id"}


def test_every_line_is_json_with_standard_fields(client: TestClient, logs: LogCapture) -> None:
    client.get("/api/v1/tools")
    get_logger("t").info("outside.request")
    logging.getLogger("uvicorn.error").info("library line")

    lines = logs.lines()  # fails on any non-JSON line
    assert len(lines) >= 3
    for line in lines:
        assert line.keys() >= STANDARD_FIELDS | SYSTEM_FIELDS, line
        assert line["service"] == "api"


def test_request_lines_carry_the_request_id(client: TestClient, logs: LogCapture) -> None:
    response = client.get("/api/v1/tools")
    request_id = response.headers["X-Request-ID"]

    (access,) = logs.events("http.request")
    assert access["request_id"] == request_id
    assert uuid.UUID(request_id).version == 7
    assert abs(uuid7_timestamp_ms(uuid.UUID(request_id)) / 1000 - time.time()) < 60


def test_valid_incoming_request_id_is_reused(client: TestClient, logs: LogCapture) -> None:
    response = client.get("/api/v1/tools", headers={"X-Request-ID": "trace-abc_123"})

    assert response.headers["X-Request-ID"] == "trace-abc_123"
    assert logs.events("http.request")[0]["request_id"] == "trace-abc_123"


@pytest.mark.parametrize(
    "bad_id",
    # Header values travel as bytes; non-ASCII arrives as raw UTF-8 octets.
    [b"has space", b"x" * 65, b"semi;colon", "ünïcode".encode(), b"ansi\x1b[31m", b"<script>"],
)
def test_unsafe_incoming_request_id_is_replaced(client: TestClient, bad_id: bytes) -> None:
    response = client.get("/api/v1/tools", headers={"X-Request-ID": bad_id})

    assert response.headers["X-Request-ID"] != bad_id.decode("latin-1")
    assert uuid.UUID(response.headers["X-Request-ID"]).version == 7


def test_access_log_records_route_template_not_raw_path(
    client: TestClient, logs: LogCapture, authenticate: Callable[[Role], Principal]
) -> None:
    authenticate(Role.VIEWER)
    client.get("/api/v1/tools?debug=1")
    client.get("/no/such/path/user-42?q=private")

    matched, unmatched = logs.events("http.request")
    assert matched["route"] == "/api/v1/tools"
    assert matched["status"] == 200
    assert matched["method"] == "GET"
    assert isinstance(matched["duration_ms"], float)
    assert unmatched["route"] == "<unmatched>"
    assert unmatched["status"] == 404
    assert "user-42" not in logs.text
    assert "private" not in logs.text
    assert "debug=1" not in logs.text


def test_health_probes_are_quiet_at_info(client: TestClient, logs: LogCapture) -> None:
    client.get("/health")
    assert logs.events("http.request") == []


def test_uvicorn_access_logger_is_silenced(app: object, logs: LogCapture) -> None:
    logging.getLogger("uvicorn.access").info('127.0.0.1 - "GET /raw?token=x HTTP/1.1" 200')
    assert logs.lines() == []


def test_sqlalchemy_engine_never_logs_parameters(app: object) -> None:
    assert logging.getLogger("sqlalchemy.engine").getEffectiveLevel() >= logging.WARNING


def test_console_format_renders(tmp_path: Path) -> None:
    import io

    stream = io.StringIO()
    settings = LoggingSettings(environment="development")
    configure_logging(settings, service="api", stream=stream)
    get_logger("t").info("hello.console", password="x-secret-x")

    assert "hello.console" in stream.getvalue()
    assert "x-secret-x" not in stream.getvalue()


def test_log_file_is_json(tmp_path: Path) -> None:
    import io

    path = tmp_path / "logs" / "sentinel.log"
    settings = LoggingSettings(environment="development", log_file_path=path)
    configure_logging(settings, service="worker", stream=io.StringIO())
    get_logger("t").info("to.file")
    for handler in logging.getLogger().handlers:
        handler.flush()

    line = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert line["event"] == "to.file"
    assert line["service"] == "worker"


def test_uvicorn_supervisor_formatter_is_structured_and_redacted() -> None:
    from app.core.logging.config import uvicorn_formatter

    record = logging.LogRecord(
        "uvicorn.error",
        logging.INFO,
        __file__,
        1,
        "Started on %s",
        ("redis://:pw123456@r/0",),
        None,
    )
    record.color_message = "\x1b[36mcoloured\x1b[0m"
    line = json.loads(uvicorn_formatter().format(record))

    assert line["service"] == "api"
    assert "color_message" not in line
    assert "pw123456" not in line["event"]
