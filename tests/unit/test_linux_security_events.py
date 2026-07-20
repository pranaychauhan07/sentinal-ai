"""Unit tests for core/linux_security/events.py."""

from __future__ import annotations

import pytest

from core.linux_security.events import (
    LinuxSecurityEvent,
    LinuxSecurityEventPublisher,
    LinuxSecurityEventType,
)

pytestmark = pytest.mark.unit


def test_subscriber_receives_published_event() -> None:
    publisher = LinuxSecurityEventPublisher()
    received: list[LinuxSecurityEvent] = []
    publisher.subscribe(received.append)

    event = LinuxSecurityEvent(
        event_type=LinuxSecurityEventType.FINDING_GENERATED, source="test", detail="x"
    )
    publisher.publish(event)

    assert received == [event]


def test_multiple_subscribers_all_receive_event() -> None:
    publisher = LinuxSecurityEventPublisher()
    counts = {"a": 0, "b": 0}
    publisher.subscribe(lambda _e: counts.__setitem__("a", counts["a"] + 1))
    publisher.subscribe(lambda _e: counts.__setitem__("b", counts["b"] + 1))

    publisher.publish(LinuxSecurityEvent(event_type=LinuxSecurityEventType.DEGRADED, source="s"))

    assert counts == {"a": 1, "b": 1}


def test_a_failing_subscriber_does_not_break_others() -> None:
    publisher = LinuxSecurityEventPublisher()
    received: list[LinuxSecurityEvent] = []

    def _boom(_event: LinuxSecurityEvent) -> None:
        raise RuntimeError("subscriber failure")

    publisher.subscribe(_boom)
    publisher.subscribe(received.append)

    publisher.publish(
        LinuxSecurityEvent(event_type=LinuxSecurityEventType.ANALYSIS_STARTED, source="s")
    )

    assert len(received) == 1


def test_publishers_are_independent_instances() -> None:
    a = LinuxSecurityEventPublisher()
    b = LinuxSecurityEventPublisher()
    received: list[LinuxSecurityEvent] = []
    a.subscribe(received.append)
    b.publish(LinuxSecurityEvent(event_type=LinuxSecurityEventType.REJECTED, source="s"))
    assert received == []
