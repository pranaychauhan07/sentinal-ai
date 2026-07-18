from __future__ import annotations

import pytest

from core.agents.confidence import ConfidenceScore
from core.agents.contracts import ExecutionPlan, ExecutionStatus, PlannedStep

pytestmark = pytest.mark.unit


def test_execution_plan_entry_steps_are_those_with_no_dependencies() -> None:
    plan = ExecutionPlan(
        steps=(
            PlannedStep(agent_name="a", depends_on=()),
            PlannedStep(agent_name="b", depends_on=("a",)),
            PlannedStep(agent_name="c", depends_on=()),
        )
    )
    assert {step.agent_name for step in plan.entry_steps} == {"a", "c"}


def test_execution_plan_is_empty_when_no_steps() -> None:
    plan = ExecutionPlan()
    assert plan.is_empty
    assert plan.entry_steps == ()


def test_execution_plan_default_confidence_is_deterministic() -> None:
    plan = ExecutionPlan()
    assert plan.confidence == ConfidenceScore.deterministic()


def test_execution_status_values_cover_documented_lifecycle() -> None:
    assert {status.value for status in ExecutionStatus} == {
        "pending",
        "running",
        "succeeded",
        "degraded",
        "failed",
        "skipped",
    }
