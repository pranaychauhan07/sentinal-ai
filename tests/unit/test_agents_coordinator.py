from __future__ import annotations

import pytest

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.agents.coordinator import CoordinatorAgent
from core.agents.planning_agent import PlanningAgent
from core.agents.registry import AgentRegistry
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


class _StubSpecialist(BaseAgent):
    name = "stub_specialist"
    description = "stub"
    capabilities = (AgentCapability(name="log_analysis"),)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="stub",
            confidence=ConfidenceScore.deterministic(),
        )


def _coordinator(registry: AgentRegistry) -> CoordinatorAgent:
    planner = PlanningAgent(agent_registry=registry)
    return CoordinatorAgent(planning_agent=planner)


def test_no_evidence_and_no_capabilities_routes_to_manual_triage() -> None:
    coordinator = _coordinator(AgentRegistry())
    state = CaseInvestigationState()
    result = coordinator(state)
    assert result.requires_manual_triage is True


def test_declared_capability_with_no_matching_agent_routes_to_manual_triage() -> None:
    coordinator = _coordinator(AgentRegistry())
    state = CaseInvestigationState(metadata={"required_capabilities": ["nothing_registered"]})
    result = coordinator(state)
    assert result.requires_manual_triage is True


def test_matched_capability_produces_a_non_empty_plan_and_no_triage() -> None:
    registry = AgentRegistry()
    registry.register(_StubSpecialist())
    coordinator = _coordinator(registry)
    state = CaseInvestigationState(metadata={"required_capabilities": ["log_analysis"]})
    result = coordinator(state)
    assert result.requires_manual_triage is False
    assert result.execution_plan is not None
    assert len(result.execution_plan.steps) == 1
    # Both the planner's and the coordinator's own reasoning are recorded.
    assert {t.agent_name for t in result.thoughts} == {"planning_agent", "coordinator"}


def test_coordinator_never_performs_domain_reasoning_itself() -> None:
    # The coordinator's only output is plan delegation/triage status — it
    # must never hold a domain-specific finding or verdict field.
    registry = AgentRegistry()
    registry.register(_StubSpecialist())
    coordinator = _coordinator(registry)
    state = CaseInvestigationState(metadata={"required_capabilities": ["log_analysis"]})
    result = coordinator(state)
    coordinator_output = result.agent_outputs["coordinator"]
    assert set(coordinator_output.output.keys()) <= {"planned_steps"}
