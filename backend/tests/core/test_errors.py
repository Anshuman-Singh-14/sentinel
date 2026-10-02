"""Errors become structured results, never stack traces (CLAUDE.md rule 8)."""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from app.core.errors import NotFound, ScopeDenied
from tests.conftest import LogCapture

LEAKY_DSN = "postgresql://sentinel_app:SuperSecretPw1@postgres:5432/sentinel"


class LoginBody(BaseModel):
    username: str
    password: str = Field(min_length=12)


@pytest.fixture
def error_client(app: FastAPI) -> Iterator[TestClient]:
    @app.get("/_test/scope")
    async def scope() -> None:
        raise ScopeDenied(details={"target": "10.0.0.5"})

    @app.get("/_test/missing")
    async def missing() -> None:
        raise NotFound("Run not found.")

    @app.get("/_test/crash")
    async def crash() -> None:
        raise RuntimeError(f"cannot connect to {LEAKY_DSN}")

    @app.post("/_test/login")
    async def login(body: LoginBody) -> dict[str, str]:
        return {"ok": body.username}

    with TestClient(app) as client:
        yield client


def _assert_error_shape(body: dict[str, object], code: str, request_id: str) -> None:
    assert set(body) == {"error"}
    error = body["error"]
    assert isinstance(error, dict)
    assert set(error) == {"code", "message", "request_id", "details"}
    assert error["code"] == code
    assert error["request_id"] == request_id


def test_sentinel_error_maps_to_status_and_code(error_client: TestClient) -> None:
    response = error_client.get("/_test/scope")

    assert response.status_code == 403
    _assert_error_shape(response.json(), "scope_denied", response.headers["X-Request-ID"])
    assert response.json()["error"]["details"] == {"target": "10.0.0.5"}


def test_custom_message_is_returned(error_client: TestClient) -> None:
    response = error_client.get("/_test/missing")

    assert response.status_code == 404
    assert response.json()["error"]["message"] == "Run not found."


def test_unhandled_exception_is_generic_500(error_client: TestClient, logs: LogCapture) -> None:
    response = error_client.get("/_test/crash")

    assert response.status_code == 500
    request_id = response.headers["X-Request-ID"]
    _assert_error_shape(response.json(), "internal_error", request_id)
    assert "RuntimeError" not in response.text
    assert "SuperSecretPw1" not in response.text
    # Security headers still apply to the last-resort response.
    assert response.headers["X-Content-Type-Options"] == "nosniff"

    # Full detail is in the server log, correlated and redacted.
    (logged,) = logs.events("http.unhandled_exception")
    assert logged["request_id"] == request_id
    assert "RuntimeError" in logged["exception"]
    assert "SuperSecretPw1" not in logs.text
    (access,) = logs.events("http.request")
    assert access["status"] == 500


def test_validation_errors_do_not_echo_input(error_client: TestClient) -> None:
    response = error_client.post(
        "/_test/login", json={"username": "alice", "password": "short-pw1", "extra": 1}
    )

    assert response.status_code == 422
    body = response.json()
    _assert_error_shape(body, "validation_failed", response.headers["X-Request-ID"])
    assert "short-pw1" not in response.text
    (error,) = body["error"]["details"]["errors"]
    assert error["loc"] == ["body", "password"]
    assert set(error) == {"loc", "msg", "type"}


def test_unknown_route_is_structured_404(error_client: TestClient) -> None:
    response = error_client.get("/nope")

    assert response.status_code == 404
    _assert_error_shape(response.json(), "not_found", response.headers["X-Request-ID"])


def test_wrong_method_is_structured_405(error_client: TestClient) -> None:
    response = error_client.delete("/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert "allow" in {key.lower() for key in response.headers}
