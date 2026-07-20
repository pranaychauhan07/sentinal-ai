"""Unit tests for core/vulnerabilities/events.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.events import (
    VulnerabilityEvent,
    VulnerabilityEventPublisher,
    VulnerabilityEventType,
)

pytestmark = pytest.mark.unit


def test_subscriber_receives_published_event() -> None:
    received: list[VulnerabilityEvent] = []
    publisher = VulnerabilityEventPublisher()
    publisher.subscribe(received.append)

    event = VulnerabilityEvent(
        event_type=VulnerabilityEventType.FINDING_GENERATED, source="scan.nessus", detail="x"
    )
    publisher.publish(event)
    assert received == [event]


def test_multiple_subscribers_all_receive_the_event() -> None:
    received_a: list[VulnerabilityEvent] = []
    received_b: list[VulnerabilityEvent] = []
    publisher = VulnerabilityEventPublisher()
    publisher.subscribe(received_a.append)
    publisher.subscribe(received_b.append)

    publisher.publish(
        VulnerabilityEvent(event_type=VulnerabilityEventType.VULNERABILITY_SCORED, source="x")
    )
    assert len(received_a) == 1
    assert len(received_b) == 1


def test_failing_subscriber_does_not_break_publish() -> None:
    def _boom(_event: VulnerabilityEvent) -> None:
        raise RuntimeError("subscriber failure")

    received: list[VulnerabilityEvent] = []
    publisher = VulnerabilityEventPublisher()
    publisher.subscribe(_boom)
    publisher.subscribe(received.append)

    publisher.publish(
        VulnerabilityEvent(event_type=VulnerabilityEventType.REJECTED, source="x")
    )  # must not raise
    assert len(received) == 1
