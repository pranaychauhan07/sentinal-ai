"""Unit tests for core/graph/state.py."""

from __future__ import annotations

import pytest

from core.graph.state import AgentThought, CaseInvestigationState


@pytest.mark.unit
def test_case_investigation_state_defaults() -> None:
    state = CaseInvestigationState()
    assert state.case_id is not None
    assert state.investigation_run_id is not None
    assert state.evidence == []
    assert state.findings == []
    assert state.thoughts == []
    assert state.requires_manual_triage is False


@pytest.mark.unit
def test_add_thought_appends_well_formed_entry() -> None:
    state = CaseInvestigationState()
    state.add_thought("soc_analyst_agent", "Detected repeated failed logins.", 0.9)

    assert len(state.thoughts) == 1
    thought = state.thoughts[0]
    assert isinstance(thought, AgentThought)
    assert thought.agent_name == "soc_analyst_agent"
    assert thought.confidence == 0.9


@pytest.mark.unit
def test_thought_confidence_is_bounded() -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - pydantic ValidationError subclasses ValueError
        AgentThought(agent_name="x", thought="y", confidence=1.5)


@pytest.mark.unit
def test_each_state_instance_gets_a_unique_case_id() -> None:
    assert CaseInvestigationState().case_id != CaseInvestigationState().case_id


@pytest.mark.unit
def test_add_error_appends_a_structured_record() -> None:
    state = CaseInvestigationState()
    state.add_error("test_agent", "SOME_CODE", "something broke")
    assert len(state.errors) == 1
    assert state.errors[0].code == "SOME_CODE"
    assert state.errors[0].agent_name == "test_agent"


@pytest.mark.unit
def test_framework_fields_default_empty_and_are_not_shared_between_instances() -> None:
    a = CaseInvestigationState()
    b = CaseInvestigationState()
    assert a.agent_outputs == {}
    assert a.execution_plan is None
    a.findings.append({"x": 1})
    a.agent_outputs["x"] = object()
    assert b.findings == []
    assert b.agent_outputs == {}


@pytest.mark.unit
def test_state_round_trips_through_model_dump_and_validate() -> None:
    state = CaseInvestigationState(metadata={"required_capabilities": ["log_analysis"]})
    state.add_thought("a", "t", 1.0)
    dumped = state.model_dump()
    rebuilt = CaseInvestigationState.model_validate(dumped)
    assert rebuilt.metadata == {"required_capabilities": ["log_analysis"]}
    assert len(rebuilt.thoughts) == 1
