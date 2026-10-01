"""FastAPI application factory.

Run with ``uvicorn app.main:create_app --factory``. A factory (instead of a
module-level ``app``) lets tests build isolated instances with their own settings.
"""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.health import router as health_router
from app.config import get_settings

# The interactive docs load scripts and styles that the strict CSP below would
# block. They are only served outside production (see create_app).
_DOCS_PATHS = frozenset({"/docs", "/openapi.json"})

# Sentinel should pass its own header checker (04-security.md section 9).
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}
# The API only returns JSON, so the page-level CSP can deny everything.
_API_CSP = "default-src 'none'; frame-ancestors 'none'"


def create_app() -> FastAPI:
    settings = get_settings()
    is_production = settings.environment == "production"

    app = FastAPI(
        title="Sentinel API",
        version=__version__,
        docs_url=None if is_production else "/docs",
        redoc_url=None,
        openapi_url=None if is_production else "/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-Request-ID", "X-CSRF-Token"],
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        if request.url.path not in _DOCS_PATHS:
            response.headers["Content-Security-Policy"] = _API_CSP
        if is_production:
            # Only meaningful once TLS terminates in front of the API (prod profile).
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.include_router(health_router)
    return app
