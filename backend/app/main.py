"""FastAPI application factory.

Run with ``uvicorn app.main:create_app --factory``. A factory (instead of a
module-level ``app``) lets tests build isolated instances with their own settings.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.health import router as health_router
from app.api.v1 import router as v1_router
from app.config import get_settings
from app.core.errors import install_exception_handlers
from app.core.http import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine
from app.engine.knowledge import get_knowledge_base
from app.engine.registry import registry

logger = get_logger("sentinel.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("app.startup", tools=len(registry))
    yield
    await dispose_engine()
    logger.info("app.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings, service="api")
    is_production = settings.environment == "production"

    # Fail fast: a broken tool or knowledge file stops startup instead of
    # surfacing later as a confusing run-time error.
    registry.discover()
    get_knowledge_base()

    app = FastAPI(
        title="Sentinel API",
        version=__version__,
        docs_url=None if is_production else "/docs",
        redoc_url=None,
        openapi_url=None if is_production else "/openapi.json",
        lifespan=lifespan,
    )
    install_exception_handlers(app)

    # Middleware added last runs first (outermost). Request flow:
    # SecurityHeaders -> RequestContext -> CORS -> routes. The request context
    # wraps CORS, so even rejected preflights are logged with a request ID, and
    # the security headers wrap everything, including the last-resort 500.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-Request-ID", "X-CSRF-Token"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware, trusted_proxies=settings.trusted_proxy_networks)
    app.add_middleware(SecurityHeadersMiddleware, hsts=is_production)

    app.include_router(health_router)
    app.include_router(v1_router)
    return app
