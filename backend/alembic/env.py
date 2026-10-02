"""Alembic migration environment (async, PostgreSQL).

Migrations connect as ``sentinel_owner``, the schema owner. Only the one-shot
``migrate`` container receives that credential (MIGRATION_DATABASE_URL). The
api and worker connect as ``sentinel_app``, which can read and write rows but
cannot create, alter or drop tables.
"""

import asyncio

from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import app.db.models  # noqa: F401  (registers models on Base.metadata)
from alembic import context
from app.config import MigrationSettings, to_async_database_url
from app.core.logging import configure_logging, get_logger
from app.db.base import Base

settings = MigrationSettings()  # migration_database_url is populated from the environment
configure_logging(settings, service="migrate")
logger = get_logger("sentinel.migrate")

target_metadata = Base.metadata
database_url = to_async_database_url(settings.migration_database_url)


def _configure(connection: Connection | None = None) -> None:
    context.configure(
        connection=connection,
        url=None if connection is not None else database_url,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        literal_binds=connection is None,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade --sql``)."""
    _configure()
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_sync)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    logger.info("migrations.start")
    asyncio.run(run_migrations_online())
    logger.info("migrations.complete")
