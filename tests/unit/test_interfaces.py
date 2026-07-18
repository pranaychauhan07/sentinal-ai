"""Unit tests for core/interfaces.py — verifies the Protocol contracts are
satisfied by conforming implementations and reject non-conforming ones."""

from __future__ import annotations

import pytest

from core.graph.state import CaseInvestigationState
from core.interfaces import Agent, Repository, Service, Tool


class _EchoAgent:
    """Minimal conforming Agent implementation for contract testing."""

    def __call__(self, state: CaseInvestigationState) -> CaseInvestigationState:
        return state


class _NotAnAgent:
    """Does not implement __call__ with the right shape (no __call__ at all)."""


class _RiskScoringTool:
    name = "risk_scoring_tool"
    description = "Computes a 0-100 risk score."

    def __call__(self, arguments: dict[str, float]) -> int:
        return round(sum(arguments.values()))


@pytest.mark.unit
def test_conforming_agent_satisfies_protocol() -> None:
    assert isinstance(_EchoAgent(), Agent)


@pytest.mark.unit
def test_non_conforming_object_fails_agent_protocol() -> None:
    assert not isinstance(_NotAnAgent(), Agent)


@pytest.mark.unit
def test_echo_agent_returns_state_unchanged() -> None:
    state = CaseInvestigationState()
    result = _EchoAgent()(state)
    assert result is state


@pytest.mark.unit
def test_conforming_tool_satisfies_protocol() -> None:
    tool = _RiskScoringTool()
    assert isinstance(tool, Tool)
    assert tool({"a": 10.0, "b": 20.0}) == 30


@pytest.mark.unit
def test_repository_protocol_is_structural_only() -> None:
    # Repository is a Protocol describing async methods; this test only
    # confirms the Protocol itself is importable and usable as a type
    # annotation target — concrete conformance is exercised in
    # tests/unit/test_base_repository.py against a real implementation.
    assert Repository is not None


@pytest.mark.unit
def test_service_is_documentation_only_and_cannot_be_instantiated() -> None:
    with pytest.raises(NotImplementedError):
        Service()
