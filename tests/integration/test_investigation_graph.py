"""Integration test: a full `build_investigation_graph()` run, compiled and
executed end-to-end via LangGraph — no mocking of the graph engine itself.

Framework-only, per this milestone's scope: no real specialist agent exists,
so these tests register minimal fake specialists (never a real
cybersecurity module) purely to prove the Coordinator -> Planner -> fan-out
-> merge pipeline works through an actually-compiled `StateGraph`.
"""

from __future__ import annotations

import pytest
from langgraph.graph import END

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.agents.registry import AgentRegistry
from core.graph.investigation_graph import build_investigation_graph, run_investigation
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.integration


class _FakeLogAgent(BaseAgent):
    name = "fake_log_agent"
    description = "test double"
    capabilities = (AgentCapability(name="log_analysis"),)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        state.findings.append({"source": self.name})
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="analyzed logs",
            confidence=ConfidenceScore.deterministic(),
        )


class _FakeEmailAgent(BaseAgent):
    name = "fake_email_agent"
    description = "test double"
    capabilities = (AgentCapability(name="email_triage"),)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        state.findings.append({"source": self.name})
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="triaged email",
            confidence=ConfidenceScore.deterministic(),
        )


def test_case_with_no_evidence_routes_straight_to_manual_triage() -> None:
    engine = build_investigation_graph(agent_registry=AgentRegistry())
    result = run_investigation(CaseInvestigationState(), engine=engine)

    assert result.requires_manual_triage is True
    assert result.agent_outputs["coordinator"].status == ExecutionStatus.DEGRADED
    # No specialist ever ran.
    assert result.findings == []


def test_default_graph_has_only_the_coordinator_as_a_node() -> None:
    engine = build_investigation_graph(agent_registry=AgentRegistry())
    assert engine.node_names == ("coordinator",)


def test_mixed_evidence_fans_out_to_both_registered_specialists() -> None:
    registry = AgentRegistry()
    registry.register(_FakeLogAgent())
    registry.register(_FakeEmailAgent())

    engine = build_investigation_graph(agent_registry=registry)
    engine.add_agent_node("fake_log_agent")
    engine.add_agent_node("fake_email_agent")
    engine.add_edge("fake_log_agent", END)
    engine.add_edge("fake_email_agent", END)
    engine.compile()

    state = CaseInvestigationState(
        evidence=["a log file", "an email"],
        metadata={"required_capabilities": ["log_analysis", "email_triage"]},
    )
    result = run_investigation(state, engine=engine)

    assert result.requires_manual_triage is False
    assert {f["source"] for f in result.findings} == {"fake_log_agent", "fake_email_agent"}
    assert set(result.agent_outputs) == {
        "coordinator",
        "planning_agent",
        "fake_log_agent",
        "fake_email_agent",
    }
    # Full ReAct trail is preserved in chronological order.
    agent_order = [t.agent_name for t in result.thoughts]
    assert agent_order[0] == "planning_agent"
    assert agent_order[1] == "coordinator"
    assert set(agent_order[2:]) == {"fake_log_agent", "fake_email_agent"}


def test_partial_capability_match_still_runs_the_matched_specialist() -> None:
    registry = AgentRegistry()
    registry.register(_FakeLogAgent())

    engine = build_investigation_graph(agent_registry=registry)
    engine.add_agent_node("fake_log_agent")
    engine.add_edge("fake_log_agent", END)
    engine.compile()

    state = CaseInvestigationState(
        evidence=["a log file"],
        metadata={"required_capabilities": ["log_analysis", "unmatched_capability"]},
    )
    result = run_investigation(state, engine=engine)

    assert result.requires_manual_triage is False
    assert result.findings == [{"source": "fake_log_agent"}]
    assert result.execution_plan is not None
    assert result.execution_plan.confidence.value < 1.0
