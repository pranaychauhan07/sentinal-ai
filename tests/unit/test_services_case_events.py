"""Unit tests for core/services/case_events.py, mirroring
tests/unit/test_findings_events.py's pattern exactly.
"""

from __future__ import annotations

import uuid

import pytest

from core.services.case_events import CaseEvent, CaseEventPublisher, CaseEventType

pytestmark = pytest.mark.unit


def test_subscriber_receives_published_event() -> None:
    publisher = CaseEventPublisher()
    received: list[CaseEvent] = []
    publisher.subscribe(received.append)

    event = CaseEvent(event_type=CaseEventType.CASE_CREATED, case_id=uuid.uuid4())
    publisher.publish(event)

    assert received == [event]


def test_subscriber_exception_does_not_break_publish() -> None:
    publisher = CaseEventPublisher()

    def _raises(_: CaseEvent) -> None:
        raise RuntimeError("boom")

    received: list[CaseEvent] = []
    publisher.subscribe(_raises)
    publisher.subscribe(received.append)

    publisher.publish(CaseEvent(event_type=CaseEventType.CASE_CLOSED, case_id=uuid.uuid4()))

    assert len(received) == 1


def test_all_eight_required_event_types_exist() -> None:
    required = {
        "case_created",
        "case_updated",
        "case_assigned",
        "case_escalated",
        "case_resolved",
        "case_closed",
        "evidence_attached",
        "finding_attached",
    }
    assert {e.value for e in CaseEventType} == required


def test_two_publishers_are_independent() -> None:
    """Constitution §2 ("avoid global state"): each `CaseEventPublisher`
    instance has its own subscriber list, never a shared module-level one."""
    first = CaseEventPublisher()
    second = CaseEventPublisher()
    received_first: list[CaseEvent] = []
    first.subscribe(received_first.append)

    second.publish(CaseEvent(event_type=CaseEventType.CASE_UPDATED, case_id=uuid.uuid4()))

    assert received_first == []
