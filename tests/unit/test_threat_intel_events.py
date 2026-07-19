"""Unit tests for core/threat_intel/events.py — ThreatIntelEventPublisher."""

from __future__ import annotations

import pytest

from core.threat_intel.events import (
    ThreatIntelEvent,
    ThreatIntelEventPublisher,
    ThreatIntelEventType,
)


@pytest.mark.unit
def test_publish_delivers_to_subscribers() -> None:
    publisher = ThreatIntelEventPublisher()
    received: list[ThreatIntelEvent] = []
    publisher.subscribe(received.append)

    event = ThreatIntelEvent(event_type=ThreatIntelEventType.IOC_EXTRACTED, source="test.log")
    publisher.publish(event)

    assert received == [event]


@pytest.mark.unit
def test_publish_swallows_subscriber_exceptions() -> None:
    publisher = ThreatIntelEventPublisher()

    def _boom(_: ThreatIntelEvent) -> None:
        raise RuntimeError("subscriber failure")

    publisher.subscribe(_boom)
    event = ThreatIntelEvent(event_type=ThreatIntelEventType.DEGRADED, source="test.log")
    publisher.publish(event)  # must not raise


@pytest.mark.unit
def test_publish_delivers_to_all_subscribers_even_if_one_fails() -> None:
    publisher = ThreatIntelEventPublisher()
    received: list[ThreatIntelEvent] = []

    def _boom(_: ThreatIntelEvent) -> None:
        raise RuntimeError("boom")

    publisher.subscribe(_boom)
    publisher.subscribe(received.append)

    event = ThreatIntelEvent(event_type=ThreatIntelEventType.SCORED, source="test.log")
    publisher.publish(event)

    assert received == [event]
