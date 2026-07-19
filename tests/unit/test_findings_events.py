"""Unit tests for core/findings/events.py."""

from __future__ import annotations

import uuid

import pytest

from core.findings.events import FindingEvent, FindingEventPublisher, FindingEventType


@pytest.mark.unit
def test_subscriber_receives_published_event() -> None:
    publisher = FindingEventPublisher()
    received: list[FindingEvent] = []
    publisher.subscribe(received.append)

    event = FindingEvent(event_type=FindingEventType.FINDING_CREATED, case_id=uuid.uuid4())
    publisher.publish(event)

    assert received == [event]


@pytest.mark.unit
def test_subscriber_exception_does_not_break_publish() -> None:
    publisher = FindingEventPublisher()

    def _raises(_: FindingEvent) -> None:
        raise RuntimeError("boom")

    received: list[FindingEvent] = []
    publisher.subscribe(_raises)
    publisher.subscribe(received.append)

    publisher.publish(
        FindingEvent(event_type=FindingEventType.FINDING_CLOSED, case_id=uuid.uuid4())
    )

    assert len(received) == 1


@pytest.mark.unit
def test_all_six_required_event_types_exist() -> None:
    required = {
        "finding_created",
        "finding_updated",
        "finding_merged",
        "technique_mapped",
        "confidence_updated",
        "finding_closed",
    }
    assert {e.value for e in FindingEventType} == required
