"""Case lifecycle domain events (ADR-0015 point 7) — the eight event types
the task requires (`CaseCreated`, `CaseUpdated`, `CaseAssigned`,
`CaseEscalated`, `CaseResolved`, `CaseClosed`, `EvidenceAttached`,
`FindingAttached`), published by `core/services/case_service.py`.

A small, self-contained in-process publisher, mirroring
`core.findings.events.FindingEventPublisher`'s shape exactly. Distinct from
`core.db.models.timeline_event.TimelineEvent`: `TimelineEvent` is the
persisted, immutable audit narrative a UI reads; `CaseEvent` is an
in-process pub-sub signal for other components (a future Report/Memory
Agent) to react to. Every `case_service.py` call site that publishes a
`CaseEvent` also records the corresponding `TimelineEvent` in the same
function — the two are always emitted together, never one without the
other, so they can never silently drift apart.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.logging import get_logger

_logger = get_logger(__name__)


class CaseEventType(StrEnum):
    CASE_CREATED = "case_created"
    CASE_UPDATED = "case_updated"
    CASE_ASSIGNED = "case_assigned"
    CASE_ESCALATED = "case_escalated"
    CASE_RESOLVED = "case_resolved"
    CASE_CLOSED = "case_closed"
    EVIDENCE_ATTACHED = "evidence_attached"
    FINDING_ATTACHED = "finding_attached"


class CaseEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: CaseEventType
    case_id: uuid.UUID
    evidence_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    detail: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


CaseEventSubscriber = Callable[[CaseEvent], None]


class CaseEventPublisher:
    """Explicit, injectable pub-sub — never a module-level mutable list
    (constitution §2, "avoid global state"). Construct one per process or
    one per test for isolation, matching
    `core.findings.events.FindingEventPublisher`'s convention."""

    def __init__(self) -> None:
        self._subscribers: list[CaseEventSubscriber] = []

    def subscribe(self, subscriber: CaseEventSubscriber) -> None:
        self._subscribers.append(subscriber)

    def publish(self, event: CaseEvent) -> None:
        _logger.info(
            "case_event",
            event_type=event.event_type.value,
            case_id=str(event.case_id),
            evidence_id=str(event.evidence_id) if event.evidence_id else None,
            finding_id=str(event.finding_id) if event.finding_id else None,
        )
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # noqa: BLE001 - a subscriber's failure must never break the pipeline
                _logger.error(
                    "case_event_subscriber_failed",
                    event_type=event.event_type.value,
                    error=str(exc),
                )
