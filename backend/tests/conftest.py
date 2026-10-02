"""Shared test configuration.

Settings are read from the environment at import time, so safe dummy values
are set before any ``app`` module is imported. Unit tests never touch real
services: dependency checks are monkeypatched.
"""

import os

# Assigned, not setdefault: tests often run inside the dev container, whose
# environment points at the real services and selects console logging.
os.environ["ENVIRONMENT"] = "test"
os.environ["LOG_LEVEL"] = "INFO"
os.environ["DATABASE_URL"] = "postgresql://test:test@127.0.0.1:1/test"
os.environ["REDIS_URL"] = "redis://:test@127.0.0.1:1/0"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
for _name in ("LOG_FORMAT", "LOG_FILE_PATH", "TRUSTED_PROXIES"):
    os.environ.pop(_name, None)

import io  # noqa: E402
import json  # noqa: E402
from collections.abc import Iterator  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.main import create_app  # noqa: E402


@dataclass
class LogCapture:
    stream: io.StringIO

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    def lines(self) -> list[dict[str, Any]]:
        """Every captured line, parsed. Fails the test if any line is not JSON."""
        return [json.loads(line) for line in self.text.splitlines() if line.strip()]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [line for line in self.lines() if line.get("event") == name]


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def logs(app: FastAPI) -> LogCapture:
    """Route all logging (JSON, the test environment's format) into a buffer.

    Depends on ``app`` so it runs after create_app, which configures logging
    to stdout.
    """
    capture = LogCapture(io.StringIO())
    configure_logging(get_settings(), service="api", stream=capture.stream)
    return capture
