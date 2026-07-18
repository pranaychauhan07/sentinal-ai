from __future__ import annotations

import pytest

from core.graph.events import EventBus, EventType, WorkflowEvent
from core.graph.metrics import MetricsCollector

pytestmark = pytest.mark.unit


def test_collector_counts_invocations_and_successes() -> None:
    bus = EventBus()
    collector = MetricsCollector(bus)

    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED, payload={"agent_name": "a"}))
    bus.publish(
        WorkflowEvent(
            event_type=EventType.AGENT_COMPLETED,
            payload={"agent_name": "a", "duration_ms": 10.0},
        )
    )

    snapshot = collector.snapshot()
    metrics = snapshot.agent_metrics["a"]
    assert metrics.invocation_count == 1
    assert metrics.success_count == 1
    assert metrics.failure_count == 0
    assert metrics.total_duration_ms == 10.0
    assert metrics.average_duration_ms == 10.0


def test_collector_counts_failures_separately_from_successes() -> None:
    bus = EventBus()
    collector = MetricsCollector(bus)

    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED, payload={"agent_name": "a"}))
    bus.publish(
        WorkflowEvent(
            event_type=EventType.AGENT_FAILED,
            payload={"agent_name": "a", "duration_ms": 5.0},
        )
    )

    metrics = collector.snapshot().agent_metrics["a"]
    assert metrics.failure_count == 1
    assert metrics.success_count == 0


def test_snapshot_is_a_deep_copy_not_a_live_reference() -> None:
    bus = EventBus()
    collector = MetricsCollector(bus)
    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED, payload={"agent_name": "a"}))

    snapshot = collector.snapshot()
    bus.publish(WorkflowEvent(event_type=EventType.AGENT_STARTED, payload={"agent_name": "a"}))

    assert snapshot.agent_metrics["a"].invocation_count == 1
    assert collector.snapshot().agent_metrics["a"].invocation_count == 2
