from __future__ import annotations

import pytest

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.agents.registry import AgentRegistry, default_agent_registry
from core.exceptions import NotFoundError
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


class _StubAgent(BaseAgent):
    name = "stub_agent"
    description = "stub"
    capabilities = (AgentCapability(name="stub_capability"),)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="stub",
            confidence=ConfidenceScore.deterministic(),
        )


def test_register_and_get_round_trips() -> None:
    registry = AgentRegistry()
    agent = _StubAgent()
    registry.register(agent)
    assert registry.get("stub_agent") is agent
    assert registry.has("stub_agent")


def test_get_missing_agent_raises_not_found() -> None:
    registry = AgentRegistry()
    with pytest.raises(NotFoundError):
        registry.get("nonexistent")


def test_find_by_capability_matches_declared_capability() -> None:
    registry = AgentRegistry()
    registry.register(_StubAgent())
    matches = registry.find_by_capability("stub_capability")
    assert len(matches) == 1
    assert matches[0].name == "stub_agent"


def test_find_by_capability_returns_empty_for_unmatched() -> None:
    registry = AgentRegistry()
    registry.register(_StubAgent())
    assert registry.find_by_capability("nothing_matches") == ()


def test_unregister_removes_the_agent() -> None:
    registry = AgentRegistry()
    registry.register(_StubAgent())
    registry.unregister("stub_agent")
    assert not registry.has("stub_agent")


def test_default_agent_registry_is_a_process_wide_singleton() -> None:
    assert default_agent_registry() is default_agent_registry()
