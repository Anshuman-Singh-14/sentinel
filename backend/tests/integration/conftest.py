"""Integration tests against real Postgres and Redis.

Run with ``docker compose --profile test run --rm test``. That service points
``TEST_DATABASE_URL`` (as ``sentinel_app``) and ``TEST_OWNER_DATABASE_URL``
(as ``sentinel_owner``) at the separate ``sentinel_test`` database, and
``TEST_REDIS_URL`` at Redis DB 15. Without them every test here is skipped.

Isolation: the schema is rebuilt with Alembic once per session (so the real
migration, grants and triggers are under test), and every test starts from
empty tables. Emptying ``audit_events`` requires disabling its append-only
trigger, which only the table owner can do: the documented limit of
in-database tamper evidence.
"""

import asyncio
import os
from collections.abc import Callable, Coroutine, Iterator
from pathlib import Path
from typing import Any

import pytest
import redis
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import RowMapping, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from alembic import command
from app.config import to_async_database_url
from app.core.auth.passwords import hash_password
from app.core.auth.roles import Role
from app.core.ids import uuid7

APP_URL = os.environ.get("TEST_DATABASE_URL")
OWNER_URL = os.environ.get("TEST_OWNER_DATABASE_URL")
REDIS_URL = os.environ.get("TEST_REDIS_URL")
BACKEND_DIR = Path(__file__).resolve().parents[2]

PASSWORD = "test-password-123"
ORIGIN = "http://localhost:5173"
CSRF_COOKIE = "__Host-sentinel_csrf"
ACCESS_COOKIE = "__Host-sentinel_access"
REFRESH_COOKIE = "__Secure-sentinel_refresh"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if APP_URL and OWNER_URL and REDIS_URL:
        return
    skip = pytest.mark.skip(
        reason="needs TEST_DATABASE_URL, TEST_OWNER_DATABASE_URL and TEST_REDIS_URL "
        "(docker compose --profile test run --rm test)"
    )
    here = Path(__file__).parent
    for item in items:
        if here in Path(str(item.path)).parents:
            item.add_marker(skip)


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine from a synchronous test (TestClient owns its own loop)."""
    return asyncio.run(coro)


class Database:
    """Direct SQL access for setup and assertions, as either role."""

    def __init__(self, app_url: str, owner_url: str) -> None:
        self._urls = {"app": app_url, "owner": owner_url}

    def execute(
        self, sql: str, params: dict[str, Any] | None = None, *, role: str = "app"
    ) -> list[RowMapping]:
        return self.script([(sql, params or {})], role=role)

    def script(
        self, statements: list[tuple[str, dict[str, Any]]], *, role: str = "app"
    ) -> list[RowMapping]:
        async def go() -> list[RowMapping]:
            engine = create_async_engine(
                to_async_database_url_str(self._urls[role]), poolclass=NullPool
            )
            try:
                async with engine.begin() as conn:
                    rows: list[RowMapping] = []
                    for sql, params in statements:
                        result = await conn.execute(text(sql), params)
                        rows = list(result.mappings().all()) if result.returns_rows else []
                    return rows
            finally:
                await engine.dispose()

        return run(go())

    def audit(self, action: str | None = None) -> list[RowMapping]:
        if action is None:
            return self.execute("SELECT * FROM audit_events ORDER BY id")
        return self.execute(
            "SELECT * FROM audit_events WHERE action = :action ORDER BY id", {"action": action}
        )

    def alerts(self) -> list[RowMapping]:
        return self.execute("SELECT * FROM security_alerts ORDER BY created_at")

    def tamper(self, sql: str, params: dict[str, Any] | None = None) -> None:
        """Modify audit_events as the owner, with the append-only trigger off."""
        self.script(
            [
                ("ALTER TABLE audit_events DISABLE TRIGGER USER", {}),
                (sql, params or {}),
                ("ALTER TABLE audit_events ENABLE TRIGGER USER", {}),
            ],
            role="owner",
        )


def to_async_database_url_str(url: str) -> str:
    return to_async_database_url(SecretStr(url))


@pytest.fixture(scope="session")
def migrated() -> None:
    assert OWNER_URL is not None
    os.environ["MIGRATION_DATABASE_URL"] = OWNER_URL
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.fixture
def db(migrated: None) -> Iterator[Database]:
    assert APP_URL is not None and OWNER_URL is not None and REDIS_URL is not None
    database = Database(APP_URL, OWNER_URL)
    database.script(
        [
            ("ALTER TABLE audit_events DISABLE TRIGGER USER", {}),
            (
                "TRUNCATE audit_events, sessions, users, security_alerts RESTART IDENTITY",
                {},
            ),
            ("ALTER TABLE audit_events ENABLE TRIGGER USER", {}),
        ],
        role="owner",
    )
    client = redis.Redis.from_url(REDIS_URL)
    client.flushdb()
    client.close()
    yield database


@pytest.fixture
def client(app: FastAPI, db: Database) -> Iterator[TestClient]:
    # https so Secure cookies are stored and sent, exactly as in a browser.
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


@pytest.fixture
def make_user(db: Database) -> Callable[..., Any]:
    """Insert a user directly (setup only; creation via the API is tested separately)."""

    def _make(username: str, role: Role = Role.ANALYST, *, is_active: bool = True) -> Any:
        user_id = uuid7()
        db.execute(
            "INSERT INTO users (id, username, password_hash, role, is_active, password_changed_at)"
            " VALUES (:id, :username, :hash, :role, :active, now())",
            {
                "id": user_id,
                "username": username,
                "hash": run(hash_password(PASSWORD)),
                "role": role.value,
                "active": is_active,
            },
        )
        return user_id

    return _make


def login(client: TestClient, username: str, password: str = PASSWORD) -> Any:
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get(CSRF_COOKIE) or "", "Origin": ORIGIN}


def save_cookies(client: TestClient) -> list[Any]:
    """Snapshot the cookie jar (domain, path and Secure flags included).

    Tests simulate several browsers by swapping jars on one client rather than
    creating more clients: every TestClient runs its own event loop, and the
    pooled database connections must stay on one loop.
    """
    return list(client.cookies.jar)


def restore_cookies(client: TestClient, cookies: list[Any]) -> None:
    client.cookies.clear()
    for cookie in cookies:
        client.cookies.jar.set_cookie(cookie)
