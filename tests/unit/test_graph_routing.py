from __future__ import annotations

import pytest
from langgraph.graph import END

from core.agents.contracts import ExecutionPlan, PlannedStep
from core.graph.routing import route_from_coordinator
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


def test_manual_triage_routes_to_end_even_with_a_plan() -> None:
    state = CaseInvestigationState(
        requires_manual_triage=True,
        execution_plan=ExecutionPlan(steps=(PlannedStep(agent_name="x"),)),
    )
    assert route_from_coordinator(state) == [END]


def test_no_plan_routes_to_end() -> None:
    state = CaseInvestigationState()
    assert route_from_coordinator(state) == [END]


def test_empty_plan_routes_to_end() -> None:
    state = CaseInvestigationState(execution_plan=ExecutionPlan())
    assert route_from_coordinator(state) == [END]


def test_plan_with_entry_steps_fans_out_to_all_of_them() -> None:
    plan = ExecutionPlan(
        steps=(
            PlannedStep(agent_name="a", depends_on=()),
            PlannedStep(agent_name="b", depends_on=()),
            PlannedStep(agent_name="c", depends_on=("a",)),
        )
    )
    state = CaseInvestigationState(execution_plan=plan)
    assert set(route_from_coordinator(state)) == {"a", "b"}
