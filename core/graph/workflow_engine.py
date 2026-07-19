"""Workflow Engine — the reusable, agent-agnostic compiler/runner that turns
registered agents into a LangGraph `StateGraph` (ADR-0003), with retry,
failure-recovery, event publication, and metrics wired around every node
uniformly. No agent, and no future milestone's specialist agent, needs to
know any of this exists — it is purely a property of *how a node runs*, not
what the node does.

Design note (verified empirically before relying on it — see the ADR):
`CaseInvestigationState`'s list/dict fields use `Annotated[..., reducer]`
merge semantics (`core/graph/state.py`) so independent agents can run in the
same LangGraph superstep without conflicting. `BaseAgent.__call__` still
returns the *full* mutated state (constitution §4.1's literal contract) —
this engine is what reconciles the two by diffing the state before/after a
node runs and returning only the changed slice as the node's update, which
is what LangGraph's reducers actually expect.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from core.agents.base import BaseAgent
from core.agents.registry import AgentRegistry
from core.exceptions import NotFoundError
from core.graph.events import EventBus, EventType, WorkflowEvent, default_event_bus
from core.graph.execution_context import execution_scope
from core.graph.failure_recovery import FailureRecoveryPolicy, recover
from core.graph.retry import RetryPolicy, run_with_retry
from core.graph.state import CaseInvestigationState

_ListFieldName = str
_DictFieldName = str

#: Field names using the `operator.add` list reducer (core/graph/state.py) —
#: diffed as "everything appended since the snapshot taken before the node
#: ran".
_LIST_FIELDS: tuple[_ListFieldName, ...] = (
    "evidence",
    "findings",
    "extracted_indicators",
    "thoughts",
    "errors",
    "execution_history",
)
#: Field names using the dict-merge reducer — diffed as "every key whose
#: value changed since the snapshot".
_DICT_FIELDS: tuple[_DictFieldName, ...] = (
    "agent_outputs",
    "confidence_scores",
    "intermediate_results",
    "metadata",
    "extensions",
)
#: Single-writer scalar fields — last-value-wins, diffed by simple equality.
_SCALAR_FIELDS: tuple[str, ...] = ("execution_plan", "requires_manual_triage")

RouterFn = Callable[[CaseInvestigationState], list[str]]


def _diff_state_update(
    before: CaseInvestigationState, after: CaseInvestigationState
) -> dict[str, Any]:
    """Compute the minimal partial update a LangGraph node should return,
    given the full state an agent produced. See module docstring."""
    update: dict[str, Any] = {}

    for field_name in _LIST_FIELDS:
        before_list = getattr(before, field_name)
        after_list = getattr(after, field_name)
        delta = after_list[len(before_list) :]
        if delta:
            update[field_name] = delta

    for field_name in _DICT_FIELDS:
        before_dict = getattr(before, field_name)
        after_dict = getattr(after, field_name)
        delta = {k: v for k, v in after_dict.items() if before_dict.get(k) != v}
        if delta:
            update[field_name] = delta

    for field_name in _SCALAR_FIELDS:
        before_value = getattr(before, field_name)
        after_value = getattr(after, field_name)
        if before_value != after_value:
            update[field_name] = after_value

    return update


class WorkflowEngine:
    """Builds and runs one LangGraph `StateGraph` over `CaseInvestigationState`.

    Every registered agent node is wrapped so it participates in the
    framework's cross-cutting concerns (events, retry, failure recovery)
    uniformly — `add_agent_node` is the only method a caller needs to add a
    new specialist agent to a workflow.
    """

    def __init__(
        self,
        *,
        agent_registry: AgentRegistry,
        event_bus: EventBus | None = None,
        retry_policy: RetryPolicy | None = None,
        recovery_policy: FailureRecoveryPolicy | None = None,
    ) -> None:
        self._agent_registry = agent_registry
        self._event_bus = event_bus or default_event_bus()
        self._retry_policy = retry_policy or RetryPolicy()
        self._recovery_policy = recovery_policy or FailureRecoveryPolicy()
        self._graph: StateGraph[CaseInvestigationState, Any, Any, Any] = StateGraph(
            CaseInvestigationState
        )
        self._node_names: list[str] = []
        self._pending_conditional_edges: list[tuple[str, RouterFn]] = []
        self._compiled: CompiledStateGraph[CaseInvestigationState, Any, Any, Any] | None = None

    @property
    def node_names(self) -> tuple[str, ...]:
        return tuple(self._node_names)

    def add_agent_node(self, agent_name: str) -> None:
        """Register `agent_name` (looked up in the `AgentRegistry`) as a
        graph node. This is the one place adding a new specialist agent
        touches this engine — no other method here changes."""
        if not self._agent_registry.has(agent_name):
            raise NotFoundError(
                f"Cannot add unregistered agent '{agent_name}' as a graph node.",
                details={"agent": agent_name},
            )
        agent = self._agent_registry.get(agent_name)
        # LangGraph's `add_node` overloads are generic over its own
        # TypedDict/dataclass/BaseModel node-input protocols in a way mypy
        # can't unify with a plain `(CaseInvestigationState) -> dict[str,
        # Any]` node function, even though this is exactly the
        # dict-partial-update shape LangGraph documents and the runtime
        # behavior is verified (tests/integration/test_investigation_graph.py).
        self._graph.add_node(agent_name, self._make_node(agent))  # type: ignore[call-overload]
        self._node_names.append(agent_name)

    def set_entry(self, agent_name: str) -> None:
        self._graph.add_edge(START, agent_name)

    def add_conditional_edges(self, source: str, router: RouterFn) -> None:
        """Registers `router` for `source`, but defers actually wiring it
        into the underlying graph until :meth:`compile`. `path_map` must
        list every node the router can return, and callers are free to add
        more nodes (`add_agent_node`) *after* calling this — resolving the
        path_map eagerly would silently exclude those, exactly the
        extensibility bug this deferral exists to avoid.
        """
        self._pending_conditional_edges.append((source, router))

    def add_edge(self, source: str, target: str) -> None:
        self._graph.add_edge(source, target)

    def compile(self) -> CompiledStateGraph[CaseInvestigationState, Any, Any, Any]:
        path_map = [*self._node_names, END]
        for source, router in self._pending_conditional_edges:
            self._graph.add_conditional_edges(source, router, path_map)
        self._compiled = self._graph.compile()
        return self._compiled

    def run(self, state: CaseInvestigationState) -> CaseInvestigationState:
        """Execute the compiled graph once, synchronously, for one case
        investigation run."""
        compiled = self._compiled or self.compile()
        case_id: UUID = state.case_id
        run_id: UUID = state.investigation_run_id
        with execution_scope(case_id=case_id, investigation_run_id=run_id):
            self._event_bus.publish(
                WorkflowEvent(
                    event_type=EventType.WORKFLOW_STARTED,
                    case_id=case_id,
                    investigation_run_id=run_id,
                )
            )
            raw_result = compiled.invoke(state)
            result = CaseInvestigationState.model_validate(raw_result)
            self._event_bus.publish(
                WorkflowEvent(
                    event_type=EventType.WORKFLOW_COMPLETED,
                    case_id=case_id,
                    investigation_run_id=run_id,
                )
            )
        return result

    def _make_node(self, agent: BaseAgent) -> Callable[[CaseInvestigationState], dict[str, Any]]:
        def node(state: CaseInvestigationState) -> dict[str, Any]:
            # LangGraph may hand the same input object to every node
            # scheduled in one superstep (verified empirically: two
            # sibling nodes both mutating a *shared* `state` in place
            # caused each other's entries to be double-counted). Each node
            # must therefore run the agent against its own private copy
            # and diff against the untouched `state` parameter — never
            # mutate `state` itself — so concurrent siblings can never see
            # (or duplicate) each other's writes.
            working_state = state.model_copy(deep=True)
            case_id, run_id = state.case_id, state.investigation_run_id
            self._event_bus.publish(
                WorkflowEvent(
                    event_type=EventType.AGENT_STARTED,
                    case_id=case_id,
                    investigation_run_id=run_id,
                    payload={"agent_name": agent.name},
                )
            )
            try:
                after = run_with_retry(
                    lambda: agent(working_state), policy=self._retry_policy, op_name=agent.name
                )
            except Exception as exc:  # noqa: BLE001 - the required core/graph boundary (constitution §9)
                duration_ms = _elapsed_ms(agent)
                self._event_bus.publish(
                    WorkflowEvent(
                        event_type=EventType.AGENT_FAILED,
                        case_id=case_id,
                        investigation_run_id=run_id,
                        payload={"agent_name": agent.name, "duration_ms": duration_ms},
                    )
                )
                after = recover(
                    exc, state=working_state, agent_name=agent.name, policy=self._recovery_policy
                )
                return _diff_state_update(state, after)

            duration_ms = _elapsed_ms(agent)
            self._event_bus.publish(
                WorkflowEvent(
                    event_type=EventType.AGENT_COMPLETED,
                    case_id=case_id,
                    investigation_run_id=run_id,
                    payload={"agent_name": agent.name, "duration_ms": duration_ms},
                )
            )
            return _diff_state_update(state, after)

        return node


def _elapsed_ms(agent: BaseAgent) -> float:
    if agent.last_execution is None:
        return 0.0
    return agent.last_execution.duration_ms
