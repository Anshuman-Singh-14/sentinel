"""structlog configuration shared by the api, worker and migrate processes.

Every log record, whether from Sentinel code (structlog) or from libraries
using stdlib ``logging`` (uvicorn, celery, sqlalchemy, alembic), goes through
the same processor chain. The result is one format, one set of standard
fields, and **one redaction step that nothing can bypass**.
"""

import logging
import logging.handlers
import sys
from typing import Any, TextIO

import structlog
from structlog.typing import EventDict, Processor

from app.config import LoggingSettings
from app.core.logging.context import SystemContextProcessor
from app.core.logging.redaction import RedactionProcessor

# Marks handlers installed here, so reconfiguring replaces only ours and
# leaves handlers from other code alone (e.g. pytest's log capture).
_HANDLER_MARKER = "_sentinel_handler"

# Library loggers and the minimum level they may emit at.
_LIBRARY_LEVELS = {
    # Our middleware writes the access log with route templates. Uvicorn's own
    # access log would record raw paths and query strings, which can carry tokens.
    "uvicorn.access": logging.WARNING,
    # INFO on sqlalchemy.engine logs SQL *with bound parameters*, i.e. user data.
    "sqlalchemy.engine": logging.WARNING,
    "sqlalchemy.pool": logging.WARNING,
    # httpx/httpcore log every request at INFO *with the full URL*. Outbound
    # calls (threat-intel APIs, header checks) can carry API keys or target
    # tokens in query strings.
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
}


def _drop_color_message(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    # Uvicorn attaches an ANSI-coloured duplicate of each message. Escape
    # sequences have no place in structured logs.
    event_dict.pop("color_message", None)
    return event_dict


def _shared_processors(settings: LoggingSettings, service: str) -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.ExtraAdder(),
        _drop_color_message,
        SystemContextProcessor(service=service, environment=settings.environment),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        # Exceptions are rendered to text *before* redaction, so a traceback
        # that echoes a DSN or token is masked too. The cost is losing the
        # console renderer's coloured tracebacks in dev; security wins.
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        RedactionProcessor(settings.log_max_field_length),
    ]


def _renderer(settings: LoggingSettings) -> Any:
    if settings.effective_log_format == "console":
        return structlog.dev.ConsoleRenderer(colors=False)
    return structlog.processors.JSONRenderer()


def _formatter(shared: list[Processor], renderer: Any) -> structlog.stdlib.ProcessorFormatter:
    return structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )


def uvicorn_formatter() -> logging.Formatter:
    """Formatter factory referenced by ``uvicorn-logging.json`` (``--log-config``).

    In dev, uvicorn's ``--reload`` supervisor process never imports the app,
    so ``configure_logging`` never runs there. This factory makes its few
    lines go through the same structured, redacting pipeline. It reads only
    logging settings, so no database or broker secrets are needed.
    """
    settings = LoggingSettings()
    return _formatter(_shared_processors(settings, "api"), _renderer(settings))


def configure_logging(
    settings: LoggingSettings,
    *,
    service: str,
    stream: TextIO | None = None,
) -> None:
    """Configure structlog and route stdlib logging through it. Safe to call again."""
    shared = _shared_processors(settings, service)

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        # Tests reconfigure logging repeatedly, and cached loggers would keep
        # the old processor chain.
        cache_logger_on_first_use=settings.environment != "test",
    )

    json_renderer = structlog.processors.JSONRenderer()
    console_renderer = _renderer(settings)

    def formatter(renderer: Any) -> structlog.stdlib.ProcessorFormatter:
        return _formatter(shared, renderer)

    handlers: list[logging.Handler] = []
    stdout_handler = logging.StreamHandler(stream or sys.stdout)
    stdout_handler.setFormatter(formatter(console_renderer))
    handlers.append(stdout_handler)

    if settings.log_file_path is not None:
        settings.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.TimedRotatingFileHandler(
            settings.log_file_path,
            when="midnight",
            backupCount=settings.log_retention_days,
            utc=True,
            encoding="utf-8",
        )
        # Files are always JSON: they are meant for machines (shipping, grep, jq).
        file_handler.setFormatter(formatter(json_renderer))
        handlers.append(file_handler)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            root.removeHandler(existing)
    for handler in handlers:
        setattr(handler, _HANDLER_MARKER, True)
        root.addHandler(handler)
    root.setLevel(settings.log_level)

    # Uvicorn and Celery install their own handlers. Strip them and let records
    # propagate to the root, so everything is rendered (and redacted) once.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "celery", "alembic"):
        library_logger = logging.getLogger(name)
        library_logger.handlers.clear()
        library_logger.propagate = True
    for name, level in _LIBRARY_LEVELS.items():
        logging.getLogger(name).setLevel(level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger
