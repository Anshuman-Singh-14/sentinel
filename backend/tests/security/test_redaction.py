"""Secrets injected into every log path must never appear in output.

03-logging-audit.md section 4. Two layers are tested: the ``redact`` function
in isolation, and the full logging pipeline end to end, through structlog,
stdlib loggers, exceptions, HTTP requests and Celery task context.
"""

import logging
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.logging import get_logger
from app.core.logging.redaction import REDACTED, redact, redact_text
from app.core.tasks.context import bind_task_context
from tests.conftest import LogCapture

# Realistic-looking fake secrets. None of them is a real credential.
PASSWORD = "Hunter2-correct-horse-battery"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
DB_PASSWORD = "s3cr3tDbPassw0rd"
DSN = f"postgresql://sentinel_app:{DB_PASSWORD}@postgres:5432/sentinel"
REDIS_PW = "r3d1sPassw0rdValue"
REDIS_URL = f"redis://:{REDIS_PW}@redis:6379/0"
RANDOM_TOKEN = "Zx9Qv2Lm8Tr4Wk7Yp1Hs6Dn3Bf5Jc0GaEuRtNqOi"  # 40 chars, high entropy
# Markers are assembled at runtime so secret scanners (detect-private-key,
# gitleaks) don't flag this fake key in the source file.
_PEM_LABEL = "RSA " + "PRIVATE KEY"
PEM = (
    f"-----BEGIN {_PEM_LABEL}-----\n"
    "MIIEowIBAAKCAQEA7bq0exampleexampleexample\n"
    f"-----END {_PEM_LABEL}-----"
)
OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

ALL_SECRETS = [PASSWORD, JWT, AWS_KEY, GITHUB_TOKEN, DB_PASSWORD, REDIS_PW, RANDOM_TOKEN, PEM]


def assert_no_secrets(text: str) -> None:
    for secret in ALL_SECRETS:
        assert secret not in text, f"secret leaked: {secret[:12]}…"


# --- redact() unit behaviour -------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWORD",
        "db_password",
        "secret",
        "api_key",
        "apiKey",
        "x-api-key",
        "Authorization",
        "cookie",
        "set-cookie",
        "refresh_token",
        "access_token",
        "private_key",
        "client_secret",
        "session",
        "dsn",
        "credentials",
    ],
)
def test_sensitive_keys_are_masked(key: str) -> None:
    assert redact({key: "value-123"}) == {key: REDACTED}


def test_nested_structures_are_masked() -> None:
    data = {"user": {"profile": {"password": PASSWORD}}, "items": [{"token": "abc"}, "ok"]}
    assert redact(data) == {
        "user": {"profile": {"password": REDACTED}},
        "items": [{"token": REDACTED}, "ok"],
    }


def test_identifier_keys_are_not_masked() -> None:
    data = {"session_id": "42", "request_id": "r-1"}
    assert redact(data) == data


def test_input_is_not_mutated() -> None:
    data = {"password": PASSWORD}
    redact(data)
    assert data == {"password": PASSWORD}


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"token is {JWT} ok", JWT),
        (f"Authorization: Bearer {RANDOM_TOKEN}", RANDOM_TOKEN),
        ("header Basic dXNlcjpwYXNzd29yZDEyMw==", "dXNlcjpwYXNzd29yZDEyMw=="),
        (f"connect failed for {DSN}", DB_PASSWORD),
        (f"broker {REDIS_URL} unreachable", REDIS_PW),
        (f"key {AWS_KEY} in config", AWS_KEY),
        (f"using {GITHUB_TOKEN}", GITHUB_TOKEN),
        (f"openai {OPENAI_KEY}", OPENAI_KEY),
        (f"login password={PASSWORD}&next=/", PASSWORD),
        (f'{{"api_key": "{RANDOM_TOKEN}"}}', RANDOM_TOKEN),
        (f"key material:\n{PEM}\nend", PEM),
    ],
)
def test_secret_patterns_in_free_text(text: str, secret: str) -> None:
    assert secret not in redact_text(text)


def test_url_keeps_non_secret_parts_for_debugging() -> None:
    assert redact_text(DSN) == "postgresql://sentinel_app:[REDACTED]@postgres:5432/sentinel"


def test_prose_is_not_redacted() -> None:
    text = "basic authentication failed; bearer header missing; token expired"
    assert redact_text(text) == text


def test_entropy_scan_only_in_credential_fields() -> None:
    # Inside a header/query/payload-like field, an unknown random token is masked.
    assert redact({"headers": {"x-custom": RANDOM_TOKEN}}) == {"headers": {"x-custom": REDACTED}}
    # Elsewhere it is kept (could be a legitimate ID or digest).
    assert redact({"note": RANDOM_TOKEN}) == {"note": RANDOM_TOKEN}


def test_hex_digests_survive_even_in_scanned_fields() -> None:
    """SHA-256 results (FIM, hash tool) must not be destroyed by the entropy rule."""
    assert redact({"payload": {"sha256": SHA256}}) == {"payload": {"sha256": SHA256}}


def test_long_values_are_truncated() -> None:
    result = redact("x" * 5000, max_length=100)
    assert result.startswith("x" * 100)
    assert result.endswith("…[truncated 4900 chars]")


def test_bytes_and_objects_are_scanned() -> None:
    assert DB_PASSWORD not in redact(DSN.encode())
    assert DB_PASSWORD not in redact(SimpleNamespace(url=DSN))


def test_deep_nesting_is_bounded() -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(50):
        child: dict[str, object] = {}
        node["n"] = child
        node = child
    assert "[MAX_DEPTH]" in str(redact(deep))


# --- End-to-end through the logging pipeline -------------------------------------


def test_structlog_kwargs(logs: LogCapture) -> None:
    get_logger("t").info(
        "login",
        password=PASSWORD,
        headers={"Authorization": f"Bearer {JWT}"},
        context={"aws": AWS_KEY, "gh": GITHUB_TOKEN},
        dsn_hint=f"using {DSN}",
    )
    assert_no_secrets(logs.text)
    assert logs.events("login")


def test_event_message_text(logs: LogCapture) -> None:
    get_logger("t").warning(f"could not reach {REDIS_URL} with key {AWS_KEY}")
    assert_no_secrets(logs.text)


def test_stdlib_logger_message_and_extra(logs: LogCapture) -> None:
    library = logging.getLogger("some.library")
    library.warning("connecting to %s", DSN, extra={"api_key": RANDOM_TOKEN, "pem": PEM})
    assert_no_secrets(logs.text)
    assert logs.lines(), "stdlib record should have been rendered"


def test_exception_tracebacks(logs: LogCapture) -> None:
    try:
        raise ConnectionError(f"could not connect to {DSN} (token {JWT})")
    except ConnectionError:
        get_logger("t").exception("db.failed")
    assert_no_secrets(logs.text)
    (line,) = logs.events("db.failed")
    assert "ConnectionError" in line["exception"]


def test_stdlib_exception_tracebacks(logs: LogCapture) -> None:
    try:
        raise RuntimeError(f"password={PASSWORD}")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("worker crashed")
    assert_no_secrets(logs.text)


def test_http_request_with_credentials(client: TestClient, logs: LogCapture) -> None:
    client.get(
        f"/does-not-exist/{GITHUB_TOKEN}?api_key={RANDOM_TOKEN}&password={PASSWORD}",
        headers={"Authorization": f"Bearer {JWT}", "Cookie": f"refresh={RANDOM_TOKEN}"},
    )
    assert_no_secrets(logs.text)
    assert logs.events("http.request")


def test_celery_task_context(logs: LogCapture) -> None:
    task = SimpleNamespace(name="sentinel.ping", request=SimpleNamespace(sentinel_request_id=JWT))
    bind_task_context(task_id="t-1", task=task)
    get_logger("worker").info("task.event", args={"password": PASSWORD})
    assert_no_secrets(logs.text)


def test_long_traceback_keeps_the_exception_line(logs: LogCapture) -> None:
    try:
        # A traceback far longer than the field limit, with the key detail at the end.
        raise ValueError("x" * 20_000 + f" final failure using {DSN}")
    except ValueError:
        get_logger("t").exception("deep.failure")

    (line,) = logs.events("deep.failure")
    assert line["exception"].startswith("[truncated ")
    assert line["exception"].endswith(
        "final failure using postgresql://sentinel_app:[REDACTED]@postgres:5432/sentinel"
    )
    assert_no_secrets(logs.text)


def test_outbound_http_client_logs_are_suppressed(logs: LogCapture) -> None:
    logging.getLogger("httpx").info(f"HTTP Request: GET https://api.example/v1?key={RANDOM_TOKEN}")
    assert logs.lines() == []
