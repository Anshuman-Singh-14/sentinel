"""Cross-site request forgery defences (04-security.md section 9, ADR 0003).

Three independent layers for cookie-authenticated, state-changing requests:

1. ``SameSite=Strict`` cookies: browsers do not attach them to cross-site
   requests at all.
2. ``Origin`` check: if the browser sends an Origin header, it must be in the
   ``CORS_ORIGINS`` allowlist.
3. Double-submit token bound to the session: the ``X-CSRF-Token`` header must
   equal the CSRF cookie *and* hash to the value stored on the session row. A
   token planted by an attacker (e.g. via a subdomain) does not match the
   session, so the binding defeats cookie-injection variants of the attack.

Login and refresh have no session yet, so they get layer 2 only. That blocks
login CSRF (forcing a victim into the attacker's account).
"""

from starlette.requests import Request

from app.config import Settings
from app.core.auth.cookies import CSRF_HEADER, cookie_names
from app.core.auth.tokens import hash_token, is_plausible_token, tokens_equal

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def origin_failure_reason(request: Request, settings: Settings) -> str | None:
    origin = request.headers.get("origin")
    # No Origin header: a non-browser client or a same-origin GET. Browsers
    # always send Origin on cross-origin POST/PUT/PATCH/DELETE.
    if origin is not None and origin not in settings.cors_origins:
        return "origin_not_allowed"
    return None


def csrf_failure_reason(request: Request, session_csrf_hash: str, settings: Settings) -> str | None:
    """Why the request fails CSRF validation, or None if it passes."""
    origin_reason = origin_failure_reason(request, settings)
    if origin_reason:
        return origin_reason
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(cookie_names(settings).csrf)
    if header is None or cookie is None:
        return "csrf_token_missing"
    if not is_plausible_token(header) or not is_plausible_token(cookie):
        return "csrf_token_missing"
    if not tokens_equal(header, cookie):
        return "csrf_token_mismatch"
    if not tokens_equal(hash_token(header), session_csrf_hash):
        return "csrf_token_invalid"
    return None
