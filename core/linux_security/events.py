"""Linux Security Analysis Framework lifecycle events — a small,
self-contained in-process publisher, independent of `core.graph.events.
EventBus` for the same leaf-layering reason documented in
`core/linux_security/metrics.py`. Mirrors
`core.vulnerabilities.events.VulnerabilityEventPublisher`'s shape exactly.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class LinuxSecurityEventType(StrEnum):
    ANALYSIS_STARTED = "analysis_started"
    CANDIDATE_DETECTED = "candidate_detected"
    CANDIDATE_SCORED = "candidate_scored"
    FINDING_GENERATED = "finding_generated"
    DEGRADED = "degraded"
    REJECTED = "rejected"
    PIPELINE_FAILED = "pipeline_failed"


class LinuxSecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: LinuxSecurityEventType
    evidence_id: uuid.UUID | None = None
    source: str
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


LinuxSecurityEventSubscriber = Callable[[LinuxSecurityEvent], None]


class LinuxSecurityEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process or
    one per test for isolation."""

    def __init__(self) -> None:
        self._subscribers: list[LinuxSecurityEventSubscriber] = []

    def subscribe(self, subscriber: LinuxSecurityEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: LinuxSecurityEvent) -> None:
        _logger.info("linux_security_event", event_type=event.event_type.value, source=event.source)
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break the pipeline
                _logger.error(
                    "linux_security_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
