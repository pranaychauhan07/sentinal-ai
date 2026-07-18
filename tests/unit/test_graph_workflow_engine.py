"""Unit tests for core/graph/workflow_engine.py using minimal fake agents —
no real specialist agent exists yet, and none of this exercises domain
reasoning."""

from __future__ import annotations

import pytest
from langgraph.graph import END

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentExecutionResult, ExecutionStatus
from core.agents.registry import AgentRegistry
from core.exceptions import ExternalServiceError, NotFoundError
from core.graph.events import EventBus
from core.graph.failure_recovery import FailureRecoveryPolicy, RecoveryAction
from core.graph.retry import RetryPolicy
from core.graph.state import CaseInvestigationState
from core.graph.workflow_engine import WorkflowEngine

pytestmark = pytest.mark.unit


class _AppendingAgent(BaseAgent):
    """Appends its own name to `state.findings` — the minimal observable
    side effect used to prove diff/merge correctness."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.description = "test"
        super().__init__()

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        state.findings.append(self.name)
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=f"appended by {self.name}",
            confidence=ConfidenceScore.deterministic(),
        )


class _ExplodingAgent(BaseAgent):
    """Simulates an exception escaping `BaseAgent.__call__` itself (a
    framework bug, not a documented agent failure mode) — the only way to
    exercise the workflow engine's own retry/failure-recovery layer, since
    `BaseAgent._execute_safely` otherwise catches everything a normal
    agent's `execute()` can raise."""

    name = "exploding_agent"
    description = "test"

    def __init__(self, *, fail_times: int = 999) -> None:
        super().__init__()
        self._fail_times = fail_times
        self.calls = 0

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:  # pragma: no cover
        raise AssertionError("not reached; __call__ is overridden for this test double")

    def __call__(self, state: CaseInvestigationState) -> CaseInvestigationState:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise ExternalServiceError("simulated framework-level failure")
        state.findings.append(self.name)
        return state


def _engine(registry: AgentRegistry, **kwargs: object) -> WorkflowEngine:
    return WorkflowEngine(agent_registry=registry, event_bus=EventBus(), **kwargs)


def test_add_agent_node_rejects_unregistered_agent() -> None:
    engine = _engine(AgentRegistry())
    with pytest.raises(NotFoundError):
        engine.add_agent_node("nonexistent")


def test_single_node_run_updates_state_correctly() -> None:
    registry = AgentRegistry()
    registry.register(_AppendingAgent("a"))
    engine = _engine(registry)
    engine.add_agent_node("a")
    engine.set_entry("a")
    engine.add_edge("a", END)
    engine.compile()

    result = engine.run(CaseInvestigationState())
    assert result.findings == ["a"]
    assert "a" in result.agent_outputs


class _NoopEntryAgent(BaseAgent):
    """Does nothing itself — exists only so the graph has a single entry
    node whose conditional edge fans out to the two parallel specialists
    under test, mirroring how `CoordinatorAgent` fans out via
    `route_from_coordinator` without depending on it here."""

    name = "entry"
    description = "test"

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="fan out",
            confidence=ConfidenceScore.deterministic(),
        )


def test_parallel_fan_out_merges_without_duplication() -> None:
    registry = AgentRegistry()
    registry.register(_NoopEntryAgent())
    registry.register(_AppendingAgent("a"))
    registry.register(_AppendingAgent("b"))
    engine = _engine(registry)
    engine.add_agent_node("entry")
    engine.add_agent_node("a")
    engine.add_agent_node("b")
    engine.set_entry("entry")
    engine.add_conditional_edges("entry", lambda state: ["a", "b"])
    engine.add_edge("a", END)
    engine.add_edge("b", END)
    engine.compile()

    result = engine.run(CaseInvestigationState())
    assert sorted(result.findings) == ["a", "b"]
    assert set(result.agent_outputs) == {"entry", "a", "b"}


def test_failure_recovery_sets_manual_triage_by_default() -> None:
    registry = AgentRegistry()
    registry.register(_ExplodingAgent())
    engine = _engine(
        registry,
        retry_policy=RetryPolicy(),
        recovery_policy=FailureRecoveryPolicy(default_action=RecoveryAction.MANUAL_TRIAGE),
    )
    engine.add_agent_node("exploding_agent")
    engine.set_entry("exploding_agent")
    engine.add_edge("exploding_agent", END)
    engine.compile()

    result = engine.run(CaseInvestigationState())
    assert result.requires_manual_triage is True
    assert len(result.errors) == 1


def test_retry_policy_lets_a_transient_failure_recover() -> None:
    registry = AgentRegistry()
    agent = _ExplodingAgent(fail_times=1)
    registry.register(agent)
    engine = _engine(registry, retry_policy=RetryPolicy(max_attempts=2, backoff_base_seconds=0.0))
    engine.add_agent_node("exploding_agent")
    engine.set_entry("exploding_agent")
    engine.add_edge("exploding_agent", END)
    engine.compile()

    result = engine.run(CaseInvestigationState())
    assert result.requires_manual_triage is False
    assert result.findings == ["exploding_agent"]
