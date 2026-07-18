"""Observability: Agent Metrics and Workflow Metrics, derived entirely from
`core.graph.events` — the metrics layer never talks to a node directly, it
only listens, so it can be attached/detached without touching
`workflow_engine.py`'s node-invocation logic.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from core.graph.events import EventBus, EventType, WorkflowEvent


class AgentMetrics(BaseModel):
    """Aggregate invocation counters for one agent across a single workflow
    run."""

    agent_name: str
    invocation_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_duration_ms: float = 0.0

    @property
    def average_duration_ms(self) -> float:
        if self.invocation_count == 0:
            return 0.0
        return self.total_duration_ms / self.invocation_count


class WorkflowMetrics(BaseModel):
    """Aggregate metrics for one full workflow run — what an operator or
    the future AI Analyst Chat's "why was this slow" question reads."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    agent_metrics: dict[str, AgentMetrics] = Field(default_factory=dict)

    @property
    def total_duration_ms(self) -> float:
        return sum(metrics.total_duration_ms for metrics in self.agent_metrics.values())


class MetricsCollector:
    """Subscribes to an `EventBus` and accumulates `WorkflowMetrics` as
    agent-lifecycle events are published. One collector instance per
    workflow run (construct fresh per `WorkflowEngine.run` call) — metrics
    are never process-wide global state, unlike the registries/settings
    singletons elsewhere in this framework, because they're scoped to one
    execution, not the process lifetime."""

    def __init__(self, event_bus: EventBus) -> None:
        self._metrics = WorkflowMetrics()
        event_bus.subscribe(EventType.AGENT_STARTED, self._on_agent_started)
        event_bus.subscribe(EventType.AGENT_COMPLETED, self._on_agent_completed)
        event_bus.subscribe(EventType.AGENT_FAILED, self._on_agent_failed)

    def snapshot(self) -> WorkflowMetrics:
        return self._metrics.model_copy(deep=True)

    def _agent_metrics(self, agent_name: str) -> AgentMetrics:
        return self._metrics.agent_metrics.setdefault(
            agent_name, AgentMetrics(agent_name=agent_name)
        )

    def _on_agent_started(self, event: WorkflowEvent) -> None:
        agent_name = event.payload.get("agent_name")
        if agent_name:
            metrics = self._agent_metrics(agent_name)
            metrics.invocation_count += 1

    def _on_agent_completed(self, event: WorkflowEvent) -> None:
        agent_name = event.payload.get("agent_name")
        if not agent_name:
            return
        metrics = self._agent_metrics(agent_name)
        metrics.success_count += 1
        metrics.total_duration_ms += float(event.payload.get("duration_ms", 0.0))

    def _on_agent_failed(self, event: WorkflowEvent) -> None:
        agent_name = event.payload.get("agent_name")
        if not agent_name:
            return
        metrics = self._agent_metrics(agent_name)
        metrics.failure_count += 1
        metrics.total_duration_ms += float(event.payload.get("duration_ms", 0.0))
