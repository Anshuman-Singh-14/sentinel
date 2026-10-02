"""HTTP-layer middleware: security headers, request context and access logging.

Both middlewares are pure ASGI rather than Starlette's ``BaseHTTPMiddleware``.
They are cheaper, they don't run the endpoint in a separate task, and they let
the outermost layer build the last-resort 500 response itself, so even that
response carries the request ID and security headers.
"""

import ipaddress
import time
from collections.abc import Iterable

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import internal_error_body
from app.core.ids import new_request_id, sanitize_request_id
from app.core.logging import get_logger
from app.core.logging.context import bind_context, clear_context

logger = get_logger("sentinel.http")

REQUEST_ID_HEADER = "X-Request-ID"

# Sentinel should pass its own header checker (04-security.md section 9).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}
# The API only returns JSON, so the page-level CSP can deny everything.
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# The interactive docs load scripts and styles that the CSP would block.
# They are only served outside production (see create_app).
DOCS_PATHS = frozenset({"/docs", "/openapi.json"})
# Probed every few seconds by Docker; logged at DEBUG to keep INFO useful.
QUIET_ROUTES = frozenset({"/health", "/ready"})

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def resolve_client_ip(
    peer_ip: str | None, forwarded_for: str | None, trusted_proxies: Iterable[IPNetwork]
) -> str | None:
    """Return the real client IP. X-Forwarded-For is honoured only from trusted proxies.

    Walk the X-Forwarded-For chain from the right (the entry closest to us),
    skipping trusted proxies. The first untrusted address is the client. Any
    hop to its left was supplied by the client and could be forged.
    """
    networks = list(trusted_proxies)

    def is_trusted(ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in networks)

    if peer_ip is None or not forwarded_for or not is_trusted(peer_ip):
        return peer_ip
    for hop in reversed([part.strip() for part in forwarded_for.split(",")]):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            # A malformed hop means the chain can't be trusted. Report the proxy.
            return peer_ip
        if not is_trusted(hop):
            return hop
    return peer_ip


def route_template(scope: Scope) -> str | None:
    """The matched route's full path template, e.g. ``/api/v1/tools``.

    FastAPI >= 0.14x resolves included routers lazily, so ``scope["route"].path``
    holds only the router-local path (``/tools``). The full template sits in
    FastAPI's per-request routing context. It is read defensively, falling back
    to the route itself. ``test_access_log_records_route_template_not_raw_path``
    pins the expected value, so a FastAPI upgrade that moves it fails CI.
    """
    context = scope.get("fastapi", {}).get("effective_route_context")
    template = getattr(context, "path_format", None)
    if isinstance(template, str):
        return template
    route = scope.get("route")
    fallback = getattr(route, "path_format", None) or getattr(route, "path", None)
    return fallback if isinstance(fallback, str) else None


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if path not in DOCS_PATHS:
                    headers["Content-Security-Policy"] = API_CSP
                if self.hsts:
                    # Only meaningful once TLS terminates in front of the API.
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestContextMiddleware:
    """Assigns a request ID, binds log context, writes the access log, and
    turns any unhandled exception into a generic, structured 500."""

    def __init__(self, app: ASGIApp, *, trusted_proxies: Iterable[IPNetwork]) -> None:
        self.app = app
        self.trusted_proxies = list(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = sanitize_request_id(headers.get(REQUEST_ID_HEADER)) or new_request_id()
        # Start every request with a clean context. Context is deliberately
        # not cleared at the end: exception handlers that run after us still
        # need the request ID.
        clear_context()
        bind_context(request_id=request_id)
        # Resolve the client IP once, here, so the access log and the audit
        # log (which reads request.state.client_ip) always agree.
        client = scope.get("client")
        client_ip = resolve_client_ip(
            client[0] if client else None, headers.get("x-forwarded-for"), self.trusted_proxies
        )
        scope.setdefault("state", {})["client_ip"] = client_ip

        if scope["type"] == "websocket":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_started = True
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception:
            # Last line of defence (CLAUDE.md rule 8): full detail goes to the
            # server log, and the client gets a generic message plus the
            # request ID to quote when reporting the problem.
            logger.exception("http.unhandled_exception")
            if response_started:
                raise
            await self._send_internal_error(send_with_request_id, request_id)
        finally:
            self._log_access(scope, status_code, started, client_ip)

    @staticmethod
    async def _send_internal_error(send: Send, request_id: str) -> None:
        body = internal_error_body(request_id)
        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _log_access(
        self, scope: Scope, status_code: int, started: float, client_ip: str | None
    ) -> None:
        # Log the route *template* (/api/v1/runs/{run_id}), never the raw
        # path or query string: those can carry identifiers or tokens.
        route_path = route_template(scope) or "<unmatched>"
        log = logger.debug if route_path in QUIET_ROUTES and status_code < 400 else logger.info
        log(
            "http.request",
            method=scope.get("method"),
            route=route_path,
            status=status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            client_ip=client_ip,
        )
