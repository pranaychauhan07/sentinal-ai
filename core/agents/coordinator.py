"""Coordinator Agent — blueprint §7: the entry point for every case.

"The coordinator should never perform domain-specific reasoning" (this
milestone's own instruction, matching blueprint §7's Coordinator card:
"Tools used: none directly — it calls the Planning Agent"). This
implementation does exactly that and nothing else: delegate to the Planning
Agent for *what* should run, and hand the resulting plan to the graph's
router (`core/graph/routing.py`) for *how* it runs (fan-out, sequencing).
Collecting specialist outputs and merging them into state happens through
the shared-state reducers (`core/graph/state.py`), not through the
Coordinator looping over agents itself — that would make the Coordinator a
second, competing execution engine instead of a planning delegator.
"""

from __future__ import annotations

from typing import ClassVar

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.agents.planning_agent import PlanningAgent
from core.graph.state import CaseInvestigationState


class CoordinatorAgent(BaseAgent):
    """Classifies whether a case is plannable at all, delegates planning to
    :class:`PlanningAgent`, and routes to manual triage when it isn't
    (blueprint §7: "if evidence type is unrecognized, routes to a
    ManualTriageRequired state ... instead of guessing")."""

    name: ClassVar[str] = "coordinator"
    description: ClassVar[str] = (
        "Entry point for every case investigation: decides whether the case "
        "is plannable and delegates planning to the Planning Agent."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Classify whether the case has any usable evidence-capability signal.",
        "Delegate execution planning to the Planning Agent.",
        "Route to manual triage when no plan can be produced.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(name="coordination", description="Orchestrates case investigations."),
    )

    def __init__(self, *, planning_agent: PlanningAgent) -> None:
        super().__init__()
        self._planning_agent = planning_agent

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        if not state.evidence and not state.metadata.get("required_capabilities"):
            state.requires_manual_triage = True
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No evidence and no declared capability signals on this case; "
                    "routing to manual triage rather than guessing."
                ),
                confidence=ConfidenceScore.deterministic(),
            )

        state = self._planning_agent(state)
        plan = state.execution_plan

        if plan is None or (plan.is_empty and not plan.steps):
            state.requires_manual_triage = True
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought="Planning produced no executable steps; routing to manual triage.",
                confidence=ConfidenceScore.deterministic(),
            )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=f"Delegated planning; {len(plan.steps)} step(s) will run next.",
            confidence=plan.confidence,
            output={"planned_steps": [step.agent_name for step in plan.steps]},
        )
