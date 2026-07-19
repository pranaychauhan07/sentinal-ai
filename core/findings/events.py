"""Finding lifecycle events — the six event types the task requires
(`FindingCreated`, `FindingUpdated`, `FindingMerged`, `TechniqueMapped`,
`ConfidenceUpdated`, `FindingClosed`), published by
`core/services/finding_service.py`'s `publish_event` stage. A small,
self-contained in-process publisher, independent of `core.graph.events.
EventBus` for the same leaf-layering reason `core/threat_intel/events.py`
documents.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class FindingEventType(StrEnum):
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_MERGED = "finding_merged"
    TECHNIQUE_MAPPED = "technique_mapped"
    CONFIDENCE_UPDATED = "confidence_updated"
    FINDING_CLOSED = "finding_closed"


class FindingEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: FindingEventType
    case_id: uuid.UUID
    finding_id: uuid.UUID | None = None
    merged_into_finding_id: uuid.UUID | None = None
    technique_id: str | None = None
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


FindingEventSubscriber = Callable[[FindingEvent], None]


class FindingEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process or
    one per test for isolation, matching
    `core.threat_intel.events.ThreatIntelEventPublisher`'s convention."""

    def __init__(self) -> None:
        self._subscribers: list[FindingEventSubscriber] = []

    def subscribe(self, subscriber: FindingEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: FindingEvent) -> None:
        _logger.info(
            "finding_event",
            event_type=event.event_type.value,
            case_id=str(event.case_id),
            finding_id=str(event.finding_id) if event.finding_id else None,
            technique_id=event.technique_id,
        )
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break the pipeline
                _logger.error(
                    "finding_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
