"""Unit tests for core/agents/base.py — exercised via minimal fake agents,
never a real specialist agent (none exist yet)."""

from __future__ import annotations

import pytest

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.exceptions import AgentExecutionError, ToolExecutionError
from core.graph.state import CaseInvestigationState
from core.tools.base import BaseTool
from core.tools.registry import ToolRegistry

pytestmark = pytest.mark.unit


class _EchoAgent(BaseAgent):
    name = "echo_agent"
    description = "Echoes a fixed thought."
    capabilities = (AgentCapability(name="echo"),)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought="echoed",
            confidence=ConfidenceScore.deterministic(),
        )


class _RaisingAgent(BaseAgent):
    name = "raising_agent"
    description = "Always raises inside execute()."

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        raise ValueError("boom")


class _ToolUsingAgent(BaseAgent):
    name = "tool_using_agent"
    description = "Uses a declared tool."
    tools_used = ("upper",)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        result = self.use_tool("upper", "hi")
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=f"tool said {result}",
            confidence=ConfidenceScore.deterministic(),
        )


class _UpperTool(BaseTool[str, str]):
    name = "upper"
    description = "Uppercases a string."

    def run(self, arguments: str) -> str:
        return arguments.upper()


def test_call_returns_the_same_state_object_mutated() -> None:
    agent = _EchoAgent()
    state = CaseInvestigationState()
    result = agent(state)
    assert result is state
    assert result.thoughts[-1].thought == "echoed"
    assert "echo_agent" in result.agent_outputs
    assert result.confidence_scores["echo_agent"] == 1.0
    assert len(result.execution_history) == 1


def test_unhandled_exception_never_escapes_call() -> None:
    agent = _RaisingAgent()
    state = CaseInvestigationState()
    result = agent(state)  # must not raise
    assert result.agent_outputs["raising_agent"].status == ExecutionStatus.FAILED
    assert len(result.errors) == 1
    assert "boom" in result.errors[0].message


def test_identity_reflects_class_attributes() -> None:
    agent = _EchoAgent()
    identity = agent.identity
    assert identity.name == "echo_agent"
    assert identity.capabilities[0].name == "echo"


def test_use_tool_rejects_undeclared_tool() -> None:
    agent = _EchoAgent()
    with pytest.raises(AgentExecutionError):
        agent.use_tool("not_declared", None)


def test_use_tool_invokes_registered_tool() -> None:
    registry = ToolRegistry()
    registry.register(_UpperTool())
    agent = _ToolUsingAgent(tool_registry=registry)
    state = CaseInvestigationState()
    result = agent(state)
    assert result.agent_outputs["tool_using_agent"].thought == "tool said HI"


def test_tool_execution_error_degrades_the_agent_result() -> None:
    class _FailingTool(BaseTool[str, str]):
        name = "upper"
        description = "Always fails."

        def run(self, arguments: str) -> str:
            raise ToolExecutionError("nope")

    registry = ToolRegistry()
    registry.register(_FailingTool())
    agent = _ToolUsingAgent(tool_registry=registry)
    state = CaseInvestigationState()
    result = agent(state)
    assert result.agent_outputs["tool_using_agent"].status == ExecutionStatus.DEGRADED
