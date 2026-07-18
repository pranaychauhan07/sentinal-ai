from __future__ import annotations

import pytest

from core.exceptions import AgentExecutionError
from core.graph.failure_recovery import FailureRecoveryPolicy, RecoveryAction, recover
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


def test_manual_triage_is_the_default_action() -> None:
    state = CaseInvestigationState()
    result = recover(
        ValueError("boom"), state=state, agent_name="a", policy=FailureRecoveryPolicy()
    )
    assert result.requires_manual_triage is True
    assert len(result.errors) == 1
    assert result.errors[0].agent_name == "a"


def test_continue_degraded_does_not_set_manual_triage() -> None:
    policy = FailureRecoveryPolicy(default_action=RecoveryAction.CONTINUE_DEGRADED)
    state = CaseInvestigationState()
    result = recover(ValueError("boom"), state=state, agent_name="a", policy=policy)
    assert result.requires_manual_triage is False
    assert len(result.errors) == 1


def test_abort_workflow_raises() -> None:
    policy = FailureRecoveryPolicy(default_action=RecoveryAction.ABORT_WORKFLOW)
    state = CaseInvestigationState()
    with pytest.raises(AgentExecutionError):
        recover(ValueError("boom"), state=state, agent_name="a", policy=policy)


def test_abort_on_specific_exception_type_raises_regardless_of_default_action() -> None:
    policy = FailureRecoveryPolicy(
        default_action=RecoveryAction.CONTINUE_DEGRADED, abort_on=(ValueError,)
    )
    state = CaseInvestigationState()
    with pytest.raises(AgentExecutionError):
        recover(ValueError("boom"), state=state, agent_name="a", policy=policy)


def test_error_is_never_silently_swallowed() -> None:
    state = CaseInvestigationState()
    recover(RuntimeError("x"), state=state, agent_name="a", policy=FailureRecoveryPolicy())
    assert state.errors[0].code == "RuntimeError"
