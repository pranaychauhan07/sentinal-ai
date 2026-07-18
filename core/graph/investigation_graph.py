"""The Case Investigation Graph — blueprint §6's `investigation_graph.py`.

Today this wires exactly one node: the Coordinator (which internally
delegates to the Planning Agent by direct call, not a graph edge — see
`core/agents/coordinator.py`'s docstring for why). No specialist agent
exists yet (Milestone M1+), so the conditional edge out of the Coordinator
currently only ever resolves to `END`.

Adding a specialist agent later means: implement it (`core/agents/`),
register it in the `AgentRegistry` passed to `build_investigation_graph`,
and add two lines here — `engine.add_agent_node(name)` and
`engine.add_edge(name, END)`. `WorkflowEngine` and `router.py` need zero
changes for that to work, which is the property this milestone's brief
asked for: "the framework should support future expansion without
modification."
"""

from __future__ import annotations

from core.agents.coordinator import CoordinatorAgent
from core.agents.planning_agent import PlanningAgent
from core.agents.registry import AgentRegistry, default_agent_registry
from core.graph.events import EventBus
from core.graph.failure_recovery import FailureRecoveryPolicy
from core.graph.retry import RetryPolicy
from core.graph.routing import route_from_coordinator
from core.graph.state import CaseInvestigationState
from core.graph.workflow_engine import WorkflowEngine


def _ensure_framework_agents_registered(registry: AgentRegistry) -> None:
    if not registry.has(PlanningAgent.name):
        registry.register(PlanningAgent(agent_registry=registry))
    if not registry.has(CoordinatorAgent.name):
        planner = registry.get(PlanningAgent.name)
        if not isinstance(planner, PlanningAgent):
            raise TypeError(
                f"Registry entry '{PlanningAgent.name}' is not a PlanningAgent instance."
            )
        registry.register(CoordinatorAgent(planning_agent=planner))


def build_investigation_graph(
    *,
    agent_registry: AgentRegistry | None = None,
    event_bus: EventBus | None = None,
    retry_policy: RetryPolicy | None = None,
    recovery_policy: FailureRecoveryPolicy | None = None,
) -> WorkflowEngine:
    """Construct the Case Investigation workflow, deliberately left
    uncompiled: `WorkflowEngine.compile`/`run` resolve node/router wiring
    lazily, so a caller (a test, or a future milestone) may still call
    `engine.add_agent_node(...)` for additional specialist agents *after*
    this returns, before running it. Returns the `WorkflowEngine` rather
    than a compiled graph directly so callers/tests can inspect
    `node_names` before running it."""
    registry = agent_registry or default_agent_registry()
    _ensure_framework_agents_registered(registry)

    engine = WorkflowEngine(
        agent_registry=registry,
        event_bus=event_bus,
        retry_policy=retry_policy,
        recovery_policy=recovery_policy,
    )
    engine.add_agent_node(CoordinatorAgent.name)
    engine.set_entry(CoordinatorAgent.name)
    engine.add_conditional_edges(CoordinatorAgent.name, route_from_coordinator)
    return engine


def run_investigation(
    state: CaseInvestigationState, *, engine: WorkflowEngine | None = None
) -> CaseInvestigationState:
    """Convenience entry point: build (or reuse) the graph and run one case
    through it. `core/services/case_service.py` (Milestone M1+) will be the
    real caller of this once a case service exists."""
    return (engine or build_investigation_graph()).run(state)
