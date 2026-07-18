"""Event System — the observability backbone the workflow engine publishes
to around every node invocation (workflow start/end, agent start/complete/
fail, tool invocation). `core/graph/metrics.py`'s `MetricsCollector` is one
subscriber; `structlog_listener` (registered by default) is another.

Deliberately a simple synchronous pub/sub, not a message queue — this is an
in-process observability hook, not an integration point with an external
system (that would be a `core/tools/<capability>_client.py` adapter,
constitution §5).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class EventType(StrEnum):
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_COMPLETED = "workflow_completed"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    AGENT_FAILED = "agent_failed"
    TOOL_INVOKED = "tool_invoked"


class WorkflowEvent(BaseModel):
    """One observability event. `payload` stays a generic dict — this is
    framework infrastructure with no fixed domain vocabulary; specific
    producers (workflow_engine.py) document the keys they emit."""

    model_config = ConfigDict(frozen=True)

    event_type: EventType
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    case_id: UUID | None = None
    investigation_run_id: UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


EventHandler = Callable[[WorkflowEvent], None]


class EventBus:
    """An explicit, injectable pub/sub bus (constitution §2, "Avoid global
    state") — construct one per process (see :func:`default_event_bus`) or
    one per test for isolation."""

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._catch_all: list[EventHandler] = []

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        self._catch_all.append(handler)

    def publish(self, event: WorkflowEvent) -> None:
        for handler in (*self._handlers.get(event.event_type, ()), *self._catch_all):
            handler(event)


def structlog_listener(event: WorkflowEvent) -> None:
    """Default catch-all handler: every published event is also a
    structured log line, at WARNING for failures and INFO otherwise
    (constitution §8 log-level table)."""
    log = _logger.warning if event.event_type is EventType.AGENT_FAILED else _logger.info
    log(
        event.event_type.value,
        case_id=str(event.case_id) if event.case_id else None,
        investigation_run_id=(
            str(event.investigation_run_id) if event.investigation_run_id else None
        ),
        **event.payload,
    )


@lru_cache
def default_event_bus() -> EventBus:
    """Process-wide singleton, matching the pattern used by
    `core.config.get_settings`/`core.agents.registry.default_agent_registry`.
    `structlog_listener` is subscribed by default so every workflow run is
    observable without any caller wiring logging manually."""
    bus = EventBus()
    bus.subscribe_all(structlog_listener)
    return bus
