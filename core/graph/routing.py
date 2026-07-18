"""Conditional-edge routing functions — the graph's own control-flow logic,
kept entirely separate from any agent's reasoning (blueprint §6: `routing.py`
"holds conditional-edge logic").

Every router here is a pure function of `CaseInvestigationState`; none of
them import a concrete agent module — they only read the `ExecutionPlan`
the Coordinator already wrote onto state, and the set of node names the
`WorkflowEngine` actually registered (never routing to an unregistered node
name, which would fail at graph-compile/run time).
"""

from __future__ import annotations

from langgraph.graph import END

from core.graph.state import CaseInvestigationState


def route_from_coordinator(state: CaseInvestigationState) -> list[str]:
    """Fan out to every entry step of the Coordinator's plan, or terminate.

    Terminates immediately if the Coordinator flagged manual triage (a case
    with no plan is not silently treated as "nothing to do" — it's an
    explicit stop, per blueprint §7's Coordinator failure handling) or if
    the plan has no steps at all.
    """
    if state.requires_manual_triage:
        return [END]
    plan = state.execution_plan
    if plan is None or plan.is_empty:
        return [END]
    targets = [step.agent_name for step in plan.entry_steps]
    return targets or [END]
