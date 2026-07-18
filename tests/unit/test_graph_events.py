from __future__ import annotations

import pytest

from core.graph.events import EventBus, EventType, WorkflowEvent, default_event_bus

pytestmark = pytest.mark.unit


def test_subscribe_receives_only_its_event_type() -> None:
    bus = EventBus()
    received: list[WorkflowEvent] = []
    bus.subscribe(EventType.AGENT_STARTED, received.append)

    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED))
    bus.publish(WorkflowEvent(event_type=EventType.AGENT_COMPLETED))

    assert len(received) == 1
    assert received[0].event_type is EventType.AGENT_STARTED


def test_subscribe_all_receives_every_event() -> None:
    bus = EventBus()
    received: list[WorkflowEvent] = []
    bus.subscribe_all(received.append)

    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED))
    bus.publish(WorkflowEvent(event_type=EventType.AGENT_COMPLETED))

    assert len(received) == 2


def test_default_event_bus_is_a_process_wide_singleton() -> None:
    assert default_event_bus() is default_event_bus()


def test_workflow_event_payload_defaults_to_empty_dict() -> None:
    event = WorkflowEvent(event_type=EventType.WORKFLOW_STARTED)
    assert event.payload == {}
