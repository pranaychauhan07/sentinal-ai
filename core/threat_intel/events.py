"""Threat Intelligence Layer lifecycle events — a small, self-contained
in-process publisher, independent of `core.graph.events.EventBus` for the
same leaf-layering reason documented in `core/threat_intel/metrics.py`.

This is the seam `core/services/threat_intel_service.py`'s `publish_event`
stage uses (task requirement: "Event Publication"). Future subscribers (a
`ThreatHuntingAgent`, a Coordinator's "new IOCs available" hook) attach here
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


class ThreatIntelEventType(StrEnum):
    EXTRACTION_STARTED = "extraction_started"
    IOC_EXTRACTED = "ioc_extracted"
    RULE_MATCHED = "rule_matched"
    SCORED = "scored"
    CLASSIFIED = "classified"
    DEGRADED = "degraded"
    REJECTED = "rejected"


class ThreatIntelEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: ThreatIntelEventType
    evidence_id: uuid.UUID | None = None
    extractor_name: str | None = None
    source: str
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


ThreatIntelEventSubscriber = Callable[[ThreatIntelEvent], None]


class ThreatIntelEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process (see
    `default_threat_intel_event_publisher`) or one per test for isolation.
    """

    def __init__(self) -> None:
        self._subscribers: list[ThreatIntelEventSubscriber] = []

    def subscribe(self, subscriber: ThreatIntelEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: ThreatIntelEvent) -> None:
        _logger.info(
            "threat_intel_event",
            event_type=event.event_type.value,
            extractor=event.extractor_name,
            source=event.source,
        )
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break the pipeline
                _logger.error(
                    "threat_intel_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
