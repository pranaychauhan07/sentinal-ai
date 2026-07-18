"""Logging Layer (context/01_blueprint.md §4).

Public surface: ``configure_logging`` (call once at process startup),
``get_logger`` (obtain a bound structlog logger), the context-binding helpers
in :mod:`core.logging.context`, and the :func:`log_execution_time` decorator.
"""

from core.logging.config import configure_logging, get_logger, log_execution_time
from core.logging.context import (
    bind_agent_name,
    bind_case_id,
    bind_investigation_run_id,
    bind_request_id,
    clear_context,
    logging_context,
    new_id,
)

__all__ = [
    "bind_agent_name",
    "bind_case_id",
    "bind_investigation_run_id",
    "bind_request_id",
    "clear_context",
    "configure_logging",
    "get_logger",
    "log_execution_time",
    "logging_context",
    "new_id",
]
