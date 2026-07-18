"""Structured-log context binding: request/case/agent/correlation IDs.

Fills the blueprint's Logging Layer (context/01_blueprint.md §4) — every log
line emitted while these are bound automatically carries them, per
context/03_engineering_constitution.md §8 ("Request IDs", "Case IDs",
"Agent IDs", "Correlation IDs"). Built on structlog's contextvars support so
binding is safe across async tasks without manual argument threading.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import structlog


def new_id() -> str:
    """Generate a new correlation-style identifier (UUID4, string form)."""
    return str(uuid.uuid4())


def bind_request_id(request_id: str | None = None) -> str:
    """Bind a request ID to the current logging context, generating one if absent."""
    value = request_id or new_id()
    structlog.contextvars.bind_contextvars(request_id=value)
    return value


def bind_case_id(case_id: str) -> None:
    """Bind the current Case's ID — every agent/tool log line during an
    investigation run inherits this without passing it explicitly."""
    structlog.contextvars.bind_contextvars(case_id=case_id)


def bind_agent_name(agent_name: str) -> None:
    """Bind the currently executing agent's name (core/agents/*)."""
    structlog.contextvars.bind_contextvars(agent_name=agent_name)


def bind_investigation_run_id(run_id: str | None = None) -> str:
    """Bind a correlation ID scoping one full graph execution for a case
    (distinct from the case-lifetime ``case_id`` — a case may be
    re-analyzed across multiple runs)."""
    value = run_id or new_id()
    structlog.contextvars.bind_contextvars(investigation_run_id=value)
    return value


def clear_context() -> None:
    """Clear all bound context variables. Call at the end of a request or
    graph run so context never leaks between unrelated executions."""
    structlog.contextvars.clear_contextvars()


@contextmanager
def logging_context(**bindings: str) -> Iterator[None]:
    """Bind arbitrary key/value context for the duration of a ``with`` block,
    automatically clearing only the keys it added on exit.

    Example:
        with logging_context(case_id=case_id, agent_name="soc_analyst_agent"):
            logger.info("agent_started")
    """
    tokens = structlog.contextvars.bind_contextvars(**bindings)
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)
