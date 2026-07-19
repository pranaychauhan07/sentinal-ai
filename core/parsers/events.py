"""Parser lifecycle events — a small, self-contained in-process publisher,
independent of `core.graph.events.EventBus` for the same leaf-layering
reason documented in `core/parsers/metrics.py` (`core/parsers` must never
import `core/graph`).

This is the seam `core/services/evidence_service.py`'s `publish_event` stage
uses. Future subscribers (a `ParserAgent`'s LLM-fallback trigger, a
Coordinator's "new evidence available" hook, the Memory Agent) attach here
without this module ever needing to know about them.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class ParserEventType(StrEnum):
    INGESTION_STARTED = "ingestion_started"
    PARSED = "parsed"
    DEGRADED = "degraded"
    REJECTED = "rejected"


class ParserEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: ParserEventType
    evidence_id: uuid.UUID | None = None
    parser_name: str | None = None
    source: str
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


ParserEventSubscriber = Callable[[ParserEvent], None]


class ParserEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process (see
    `default_parser_event_publisher`) or one per test for isolation.
    """

    def __init__(self) -> None:
        self._subscribers: list[ParserEventSubscriber] = []

    def subscribe(self, subscriber: ParserEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: ParserEvent) -> None:
        _logger.info(
            "parser_event",
            event_type=event.event_type.value,
            parser=event.parser_name,
            source=event.source,
        )
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break ingestion
                _logger.error(
                    "parser_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
