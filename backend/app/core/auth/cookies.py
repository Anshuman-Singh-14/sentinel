"""Session cookies (03-logging-audit.md section 1, ADR 0003).

* **access** (HttpOnly, ``Path=/``): sent with every API call. JavaScript can
  never read it, so an XSS bug cannot steal it.
* **refresh** (HttpOnly, ``Path=/api/v1/auth``): only travels to the auth
  endpoints, so it is exposed far less often.
* **csrf** (readable, ``Path=/``): our frontend reads it and echoes it in the
  ``X-CSRF-Token`` header.

All are ``SameSite=Strict`` (never sent on cross-site requests). With
``Secure`` on, the ``__Host-`` prefix makes the browser refuse the cookie
unless it is Secure, has ``Path=/`` and no ``Domain``, so a sibling subdomain
cannot plant or overwrite it. The refresh cookie needs a narrower path, so it
uses ``__Secure-``, which only requires ``Secure``.
"""

from dataclasses import dataclass
from datetime import datetime

from starlette.responses import Response

from app.config import Settings

REFRESH_COOKIE_PATH = "/api/v1/auth"
CSRF_HEADER = "X-CSRF-Token"


@dataclass(frozen=True)
class CookieNames:
    access: str
    refresh: str
    csrf: str


def cookie_names(settings: Settings) -> CookieNames:
    if settings.cookie_secure:
        return CookieNames(
            access="__Host-sentinel_access",
            refresh="__Secure-sentinel_refresh",
            csrf="__Host-sentinel_csrf",
        )
    # Prefixed names are rejected by browsers without Secure, so the
    # dev-only insecure mode uses plain names.
    return CookieNames(access="sentinel_access", refresh="sentinel_refresh", csrf="sentinel_csrf")


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    csrf_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


def _max_age(expires_at: datetime, now: datetime) -> int:
    return max(0, int((expires_at - now).total_seconds()))


def set_session_cookies(
    response: Response, tokens: IssuedTokens, settings: Settings, *, now: datetime
) -> None:
    names = cookie_names(settings)
    response.set_cookie(
        names.access,
        tokens.access_token,
        max_age=_max_age(tokens.access_expires_at, now),
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    response.set_cookie(
        names.refresh,
        tokens.refresh_token,
        max_age=_max_age(tokens.refresh_expires_at, now),
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    response.set_cookie(
        names.csrf,
        tokens.csrf_token,
        max_age=_max_age(tokens.refresh_expires_at, now),
        path="/",
        httponly=False,  # by design: the frontend must read it to send the header
        secure=settings.cookie_secure,
        samesite="strict",
    )


def clear_session_cookies(response: Response, settings: Settings) -> None:
    names = cookie_names(settings)
    for name, path in (
        (names.access, "/"),
        (names.refresh, REFRESH_COOKIE_PATH),
        (names.csrf, "/"),
    ):
        response.delete_cookie(
            name, path=path, secure=settings.cookie_secure, httponly=True, samesite="strict"
        )
