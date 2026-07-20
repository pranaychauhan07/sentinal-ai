"""Vulnerability Assessment Framework lifecycle events — a small,
self-contained in-process publisher, independent of `core.graph.events.
EventBus` for the same leaf-layering reason documented in
`core/vulnerabilities/metrics.py`. Mirrors
`core.threat_intel.events.ThreatIntelEventPublisher`'s shape exactly.

This is the seam `core/services/vulnerability_service.py`'s
`publish_event` stage uses (task requirement: "Audit Events"). Future
subscribers (a case-notification hook, a dashboard) attach here without
this module ever needing to know about them.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class VulnerabilityEventType(StrEnum):
    EXTRACTION_STARTED = "extraction_started"
    VULNERABILITY_EXTRACTED = "vulnerability_extracted"
    VULNERABILITY_DEDUPLICATED = "vulnerability_deduplicated"
    VULNERABILITY_SCORED = "vulnerability_scored"
    FINDING_GENERATED = "finding_generated"
    DEGRADED = "degraded"
    REJECTED = "rejected"
    PIPELINE_FAILED = "pipeline_failed"


class VulnerabilityEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: VulnerabilityEventType
    evidence_id: uuid.UUID | None = None
    extractor_name: str | None = None
    source: str
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


VulnerabilityEventSubscriber = Callable[[VulnerabilityEvent], None]


class VulnerabilityEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process or
    one per test for isolation."""

    def __init__(self) -> None:
        self._subscribers: list[VulnerabilityEventSubscriber] = []

    def subscribe(self, subscriber: VulnerabilityEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: VulnerabilityEvent) -> None:
        _logger.info(
            "vulnerability_event",
            event_type=event.event_type.value,
            extractor=event.extractor_name,
            source=event.source,
        )
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break the pipeline
                _logger.error(
                    "vulnerability_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
