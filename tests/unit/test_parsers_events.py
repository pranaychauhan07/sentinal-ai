"""Unit tests for core/parsers/events.py."""

from __future__ import annotations

import pytest

from core.parsers.events import ParserEvent, ParserEventPublisher, ParserEventType


@pytest.mark.unit
def test_publish_notifies_all_subscribers() -> None:
    publisher = ParserEventPublisher()
    received: list[ParserEvent] = []
    publisher.subscribe(received.append)
    publisher.subscribe(received.append)

    event = ParserEvent(event_type=ParserEventType.PARSED, source="a.log")
    publisher.publish(event)

    assert len(received) == 2
    assert received[0] is event


@pytest.mark.unit
def test_publish_survives_a_failing_subscriber() -> None:
    publisher = ParserEventPublisher()
    received: list[ParserEvent] = []

    def _broken_subscriber(_event: ParserEvent) -> None:
        raise RuntimeError("boom")

    publisher.subscribe(_broken_subscriber)
    publisher.subscribe(received.append)

    # Must not raise, and the well-behaved subscriber must still run.
    publisher.publish(ParserEvent(event_type=ParserEventType.REJECTED, source="b.log"))
    assert len(received) == 1


@pytest.mark.unit
def test_publish_with_no_subscribers_is_a_noop() -> None:
    publisher = ParserEventPublisher()
    publisher.publish(ParserEvent(event_type=ParserEventType.INGESTION_STARTED, source="c.log"))
