"""Unit tests for RBAC, CSRF, cookies, the rate limiter and auth settings.

Database-backed behaviour (login, sessions, audit rows) lives in
tests/integration.
"""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response

from app.config import Settings, get_settings
from app.core.auth.cookies import IssuedTokens, cookie_names, set_session_cookies
from app.core.auth.csrf import csrf_failure_reason
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role, role_allows
from app.core.auth.tokens import hash_token, new_token
from app.core.errors import RateLimited
from app.core.ratelimit import MemoryRateLimiter, raise_if_limited
from app.db.models._types import utcnow
from tests.conftest import FakeAudit

# ------------------------------------------------------------------ roles


@pytest.mark.parametrize(
    ("actual", "required", "allowed"),
    [
        (Role.ADMIN, Role.ADMIN, True),
        (Role.ADMIN, Role.ANALYST, True),
        (Role.ADMIN, Role.VIEWER, True),
        (Role.ANALYST, Role.ADMIN, False),
        (Role.ANALYST, Role.ANALYST, True),
        (Role.ANALYST, Role.VIEWER, True),
        (Role.VIEWER, Role.ADMIN, False),
        (Role.VIEWER, Role.ANALYST, False),
        (Role.VIEWER, Role.VIEWER, True),
    ],
)
def test_role_hierarchy_is_exhaustive(actual: Role, required: Role, allowed: bool) -> None:
    assert role_allows(actual, required) is allowed


ADMIN_ROUTES = [
    ("GET", "/api/v1/admin/users"),
    ("POST", "/api/v1/admin/audit/verify"),
    ("GET", "/api/v1/admin/audit"),
    ("GET", "/api/v1/admin/alerts"),
]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_non_admins_are_denied_and_audited(
    client: TestClient,
    authenticate: Callable[[Role], Principal],
    fake_audit: FakeAudit,
    role: Role,
    method: str,
    path: str,
) -> None:
    principal = authenticate(role)
    response = client.request(method, path)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"
    (record,) = fake_audit.records
    assert record["action"] == "auth.access.denied"
    assert record["reason"] == "insufficient_role"
    assert record["actor"].user_id == principal.user_id
    assert record["details"] == {"required_role": "admin", "role": role.value}
    assert record["target"] == f"{method} {path}"


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_admin_routes_require_authentication(client: TestClient, method: str, path: str) -> None:
    assert client.request(method, path).status_code == 401


# ------------------------------------------------------------------- csrf


def _request(
    method: str = "POST", headers: dict[str, str] | None = None, cookies: str = ""
) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        raw.append((b"cookie", cookies.encode()))
    return Request({"type": "http", "method": method, "headers": raw, "path": "/"})


def test_csrf_passes_with_matching_bound_token() -> None:
    settings = get_settings()
    token = new_token()
    name = cookie_names(settings).csrf
    request = _request(
        headers={"X-CSRF-Token": token, "Origin": "http://localhost:5173"},
        cookies=f"{name}={token}",
    )
    assert csrf_failure_reason(request, hash_token(token), settings) is None


def test_csrf_failures() -> None:
    settings = get_settings()
    name = cookie_names(settings).csrf
    token, other = new_token(), new_token()

    def reason(headers: dict[str, str], cookies: str, session_token: str = token) -> str | None:
        return csrf_failure_reason(
            _request(headers=headers, cookies=cookies), hash_token(session_token), settings
        )

    assert reason({"X-CSRF-Token": token, "Origin": "https://evil.example"}, f"{name}={token}") == (
        "origin_not_allowed"
    )
    assert reason({"Origin": "null", "X-CSRF-Token": token}, f"{name}={token}") == (
        "origin_not_allowed"
    )
    assert reason({}, f"{name}={token}") == "csrf_token_missing"
    assert reason({"X-CSRF-Token": token}, "") == "csrf_token_missing"
    assert reason({"X-CSRF-Token": token}, f"{name}={other}") == "csrf_token_mismatch"
    # Attacker plants matching header and cookie, but not this session's token.
    assert reason({"X-CSRF-Token": other}, f"{name}={other}") == "csrf_token_invalid"


# ---------------------------------------------------------------- cookies


def _cookie_headers(settings: Settings) -> list[str]:
    response = Response()
    now = utcnow()
    tokens = IssuedTokens("a" * 43, "r" * 43, "c" * 43, now, now)
    set_session_cookies(response, tokens, settings, now=now)
    return [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]


def test_secure_cookies_use_host_prefix_and_strict_flags() -> None:
    access, refresh, csrf = _cookie_headers(get_settings())

    assert access.startswith("__Host-sentinel_access=")
    assert refresh.startswith("__Secure-sentinel_refresh=")
    assert csrf.startswith("__Host-sentinel_csrf=")
    for header in (access, refresh, csrf):
        lowered = header.lower()
        assert "secure" in lowered
        assert "samesite=strict" in lowered
    assert "httponly" in access.lower()
    assert "httponly" in refresh.lower()
    assert "httponly" not in csrf.lower()  # the frontend must read it
    assert "path=/api/v1/auth" in refresh.lower()


def test_insecure_dev_cookies_drop_prefixes() -> None:
    settings = get_settings().model_copy(update={"cookie_secure": False})
    names = cookie_names(settings)
    assert names.access == "sentinel_access"
    assert all("secure" not in h.lower().split("; ") for h in _cookie_headers(settings))


# ------------------------------------------------------------- rate limit


async def test_memory_rate_limiter_window() -> None:
    limiter = MemoryRateLimiter()
    results = [await limiter.hit("k", limit=3, window_seconds=60) for _ in range(4)]

    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].retry_after >= 1
    assert (await limiter.hit("other", limit=3, window_seconds=60)).allowed


async def test_rate_limited_error_carries_retry_after() -> None:
    limiter = MemoryRateLimiter()
    await limiter.hit("k", limit=1, window_seconds=30)
    with pytest.raises(RateLimited) as exc_info:
        raise_if_limited(await limiter.hit("k", limit=1, window_seconds=30))
    assert exc_info.value.headers["Retry-After"].isdigit()


# --------------------------------------------------------------- settings


def test_production_refuses_insecure_cookies() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings(
            environment="production",
            cookie_secure=False,
            database_url="postgresql://x:x@db/x",
            redis_url="redis://:x@redis/0",
        )


def test_lockout_max_must_cover_base() -> None:
    with pytest.raises(ValidationError, match="LOCKOUT_MAX_SECONDS"):
        Settings(
            lockout_base_seconds=600,
            lockout_max_seconds=60,
            database_url="postgresql://x:x@db/x",
            redis_url="redis://:x@redis/0",
        )
