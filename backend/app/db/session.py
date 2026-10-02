"""Async database engine and sessions.

One engine (and connection pool) per process, created lazily on first use.
Lazy creation matters for Celery: the prefork parent never touches the
database, so no pooled connection is ever shared across a fork.

Sessions never auto-commit. Service code commits explicitly, which keeps
transaction boundaries visible and reviewable.
"""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings, get_settings, to_async_database_url

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def create_engine(settings: Settings, *, application_name: str = "sentinel") -> AsyncEngine:
    return create_async_engine(
        to_async_database_url(settings.database_url),
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_pre_ping=True,  # drop dead connections (e.g. after a Postgres restart)
        pool_recycle=1800,
        # Never True: SQLAlchemy echo logs SQL together with bound parameters.
        echo=False,
        connect_args={
            "timeout": settings.database_connect_timeout_seconds,
            "server_settings": {
                "application_name": application_name,
                "statement_timeout": str(settings.database_statement_timeout_ms),
            },
        },
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(settings, application_name=f"sentinel-{settings.environment}")
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request, always closed."""
    async with get_sessionmaker()() as session:
        yield session


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


def forget_engine() -> None:
    """Abandon the engine without awaiting its disposal.

    Used when the event loop it is bound to is being thrown away (a Celery
    task interrupted mid-await). Awaiting ``dispose()`` there is impossible;
    the next ``get_engine()`` builds a fresh pool on the new loop.
    """
    global _engine, _sessionmaker
    _engine = None
    _sessionmaker = None
