from __future__ import annotations

import pytest

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.agents.planning_agent import RESERVED_FRAMEWORK_AGENT_NAMES, PlanningAgent
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


def test_no_declared_capabilities_produces_an_empty_plan() -> None:
    registry = AgentRegistry()
    planner = PlanningAgent(agent_registry=registry)
    state = CaseInvestigationState()
    result_state = planner(state)
    assert result_state.execution_plan is not None
    assert result_state.execution_plan.is_empty


def test_matched_capability_produces_a_planned_step() -> None:
    registry = AgentRegistry()
    registry.register(_StubSpecialist())
    planner = PlanningAgent(agent_registry=registry)
    state = CaseInvestigationState(metadata={"required_capabilities": ["log_analysis"]})
    result_state = planner(state)
    plan = result_state.execution_plan
    assert plan is not None
    assert [step.agent_name for step in plan.steps] == ["stub_specialist"]
    assert plan.confidence.value == 1.0


def test_unmatched_capability_produces_a_degraded_partial_plan() -> None:
    registry = AgentRegistry()
    planner = PlanningAgent(agent_registry=registry)
    state = CaseInvestigationState(metadata={"required_capabilities": ["unmatched_capability"]})
    result_state = planner(state)
    plan = result_state.execution_plan
    assert plan is not None
    assert plan.steps == ()
    assert plan.confidence.value < 1.0
    assert result_state.agent_outputs["planning_agent"].status == ExecutionStatus.DEGRADED


def test_framework_agents_are_never_matched_as_plan_targets() -> None:
    registry = AgentRegistry()
    planner = PlanningAgent(agent_registry=registry)
    registry.register(planner)
    state = CaseInvestigationState(metadata={"required_capabilities": ["planning"]})
    result_state = planner(state)
    plan = result_state.execution_plan
    assert plan is not None
    assert all(step.agent_name not in RESERVED_FRAMEWORK_AGENT_NAMES for step in plan.steps)
