"""``BaseAgent`` — the concrete base every agent in `core/agents/*.py`
inherits from (context/03_engineering_constitution.md §4).

Framework-only: no domain reasoning lives here. `BaseAgent` implements the
mechanical parts of the constitution's agent contract so a concrete
specialist agent (Milestone M1+) only has to implement `execute()` — identity,
validation, tool/memory access, the ReAct `thought` + `confidence` output
shape, structured logging, and typed error handling all come for free.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar

from core.agents.confidence import ConfidenceScore
from core.agents.contracts import (
    AgentCapability,
    AgentExecutionResult,
    AgentIdentity,
    ExecutionMetadata,
    ExecutionStatus,
)
from core.exceptions import AgentExecutionError, ToolExecutionError
from core.graph.state import CaseInvestigationState
from core.logging import get_logger, logging_context
from core.memory.interfaces import CaseMemory
from core.tools.base import BaseTool
from core.tools.registry import ToolRegistry


class BaseAgent(ABC):
    """Template-method base implementing `core.interfaces.Agent`.

    Concrete subclasses declare identity via class attributes and implement
    :meth:`execute` (the only method holding actual reasoning/logic).
    `__call__` — the single entry point per constitution §4.1 — owns the
    lifecycle around it: logging context binding, timing, error handling,
    and folding the result back onto `CaseInvestigationState`.
    """

    #: Stable, unique agent name (constitution §2 naming: matches
    #: `run_<agent_name>` convention used for the LangGraph node it becomes).
    name: ClassVar[str]
    description: ClassVar[str]
    responsibilities: ClassVar[tuple[str, ...]] = ()
    capabilities: ClassVar[tuple[AgentCapability, ...]] = ()
    #: Declared explicitly, not discovered implicitly by import
    #: (constitution §4.5).
    tools_used: ClassVar[tuple[str, ...]] = ()

    def __init__(
        self,
        *,
        tool_registry: ToolRegistry | None = None,
        case_memory: CaseMemory | None = None,
    ) -> None:
        self._tool_registry = tool_registry
        self._case_memory = case_memory
        self._logger = get_logger(self.__class__.__module__)
        #: Set after every `__call__` — the agent-level execution metadata
        #: the workflow engine's metrics collector also derives events from.
        self.last_execution: ExecutionMetadata | None = None

    @property
    def identity(self) -> AgentIdentity:
        return AgentIdentity(
            name=self.name,
            description=self.description,
            responsibilities=self.responsibilities,
            capabilities=self.capabilities,
        )

    def __call__(self, state: CaseInvestigationState) -> CaseInvestigationState:
        """The one sanctioned entry point (constitution §4.1). Never
        overridden by subclasses — override :meth:`execute` instead."""
        with logging_context(agent_name=self.name, case_id=str(state.case_id)):
            started_at = datetime.now(UTC)
            result = self._execute_safely(state)
            completed_at = datetime.now(UTC)

            self.last_execution = ExecutionMetadata(
                agent_name=self.name,
                status=result.status,
                started_at=started_at,
                completed_at=completed_at,
                error=None if result.status != ExecutionStatus.FAILED else result.thought,
            )
            result = result.model_copy(update={"metadata": self.last_execution})

            self._logger.info(
                "agent_reasoning",
                agent_name=self.name,
                status=result.status.value,
                confidence=result.confidence.value,
                thought=result.thought,
            )
            state.add_thought(self.name, result.thought, result.confidence.value)
            state.agent_outputs = {**state.agent_outputs, self.name: result}
            state.confidence_scores = {
                **state.confidence_scores,
                self.name: result.confidence.value,
            }
            state.execution_history = [*state.execution_history, self.last_execution]
            if result.status == ExecutionStatus.FAILED:
                state.add_error(self.name, "AGENT_EXECUTION_FAILED", result.thought)
            return state

    def _execute_safely(self, state: CaseInvestigationState) -> AgentExecutionResult:
        """Wraps `execute()` so an unexpected exception never escapes the
        node function into the graph (constitution §4.7, §9) — it is always
        converted into a typed, degraded `AgentExecutionResult` instead."""
        try:
            self.validate_input(state)
            return self.execute(state)
        except ToolExecutionError as exc:
            self._logger.warning("agent_tool_failure", agent_name=self.name, error=str(exc))
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=f"A required tool failed ({exc.message}); result is degraded.",
                confidence=ConfidenceScore.llm_fallback(0.0, rationale=str(exc)),
            )
        except AgentExecutionError:
            raise
        except Exception as exc:  # noqa: BLE001 - the required conversion boundary itself
            self._logger.error("agent_execution_failed", agent_name=self.name, error=str(exc))
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.FAILED,
                thought=f"Unhandled error during execution: {exc}",
                confidence=ConfidenceScore.llm_fallback(0.0, rationale=str(exc)),
            )

    def validate_input(self, state: CaseInvestigationState) -> None:  # noqa: B027 - intentional optional hook, not abstract
        """Hook for subclasses needing input validation beyond
        `CaseInvestigationState`'s own Pydantic validation (e.g. "this agent
        requires at least one evidence item"). No-op by default."""

    @abstractmethod
    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        """The agent's actual reasoning. Subclasses implement only this."""
        raise NotImplementedError

    def use_tool(self, tool_name: str, arguments: object, *, approved: bool = False) -> object:
        """Look up and invoke a declared tool (constitution §4.5, "an agent
        never inlines a calculation a tool could perform"). Raises
        `core.exceptions.NotFoundError` if `tool_name` isn't declared on
        this agent or isn't registered, and propagates
        `ToolExecutionError` for the caller (`_execute_safely`) to convert
        into a degraded result."""
        if tool_name not in self.tools_used:
            raise AgentExecutionError(
                f"Agent '{self.name}' attempted to use undeclared tool '{tool_name}'.",
                details={"agent": self.name, "tool": tool_name, "declared": self.tools_used},
            )
        if self._tool_registry is None:
            raise AgentExecutionError(
                f"Agent '{self.name}' has no tool registry configured.",
                details={"agent": self.name, "tool": tool_name},
            )
        tool: BaseTool = self._tool_registry.get(tool_name)
        self._logger.debug("tool_invoked", agent_name=self.name, tool=tool_name)
        return tool(arguments, approved=approved)
