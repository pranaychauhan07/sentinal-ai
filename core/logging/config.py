"""Structured logging configuration (structlog + stdlib logging integration).

Configures JSON logs in production, human-readable console logs in
development/testing, always additionally writing to a rotating file handler
under ``settings.log_dir`` — see core/logging/README (folder purpose lives in
logs/README.md) and context/03_engineering_constitution.md §8.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Awaitable, Callable
from logging.handlers import RotatingFileHandler
from typing import Any, TypeVar, cast

import structlog

from core.config import Settings

_LOG_FILE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
_LOG_FILE_BACKUP_COUNT = 14  # ~2 weeks of daily-sized rotation (docs/engineering-standards.md)

_configured = False

_SHARED_PROCESSORS: list[structlog.types.Processor] = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]


def configure_logging(settings: Settings, *, force: bool = False) -> None:
    """Configure structlog + stdlib logging for the process.

    Idempotent by default (safe to call from multiple entry points — the app
    factory, a script, a test fixture); pass ``force=True`` to reconfigure
    (used by test fixtures that need a clean handler set per test run).
    """
    global _configured
    if _configured and not force:
        return

    settings.log_dir.mkdir(parents=True, exist_ok=True)

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if settings.app_env.is_production
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=_SHARED_PROCESSORS,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    file_handler = RotatingFileHandler(
        settings.log_dir / "app.log",
        maxBytes=_LOG_FILE_MAX_BYTES,
        backupCount=_LOG_FILE_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [file_handler]
    if not settings.app_env.is_production:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    root_logger = logging.getLogger()
    root_logger.handlers = handlers
    root_logger.setLevel(settings.log_level)

    structlog.configure(
        processors=[
            *_SHARED_PROCESSORS,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger. ``configure_logging`` must have already
    been called (the app factory / test fixtures do this at startup)."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))


_F = TypeVar("_F", bound=Callable[..., Any])


def log_execution_time(logger: structlog.stdlib.BoundLogger | None = None) -> Callable[[_F], _F]:
    """Decorator logging a function's execution time in milliseconds.

    Works for both sync and async callables. Logged at DEBUG — call sites
    that need this visible at INFO should log it themselves with domain
    context (e.g. an agent logging its own duration alongside its thought).
    """

    def decorator(func: _F) -> _F:
        active_logger = logger or get_logger(func.__module__)

        if _is_async_callable(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.perf_counter()
                try:
                    return await cast(Callable[..., Awaitable[Any]], func)(*args, **kwargs)
                finally:
                    duration_ms = round((time.perf_counter() - start) * 1000, 2)
                    active_logger.debug(
                        "function_executed", function=func.__qualname__, duration_ms=duration_ms
                    )

            return cast(_F, async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = round((time.perf_counter() - start) * 1000, 2)
                active_logger.debug(
                    "function_executed", function=func.__qualname__, duration_ms=duration_ms
                )

        return cast(_F, sync_wrapper)

    return decorator


def _is_async_callable(func: Callable[..., Any]) -> bool:
    import inspect

    return inspect.iscoroutinefunction(func)
