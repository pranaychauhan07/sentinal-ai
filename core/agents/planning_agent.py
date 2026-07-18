"""Planning Agent — blueprint §7: "For cases with 2+ evidence types ...
decides investigation order and what correlations to attempt."

Framework-only implementation: capability-matching is entirely generic
(string tags), with zero cybersecurity-specific logic. A concrete evidence
classifier (Milestone M1+) populates ``state.metadata["required_capabilities"]``;
this agent doesn't know or care what those strings mean.
"""

from __future__ import annotations

from typing import ClassVar

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import (
    AgentCapability,
    AgentExecutionResult,
    ExecutionPlan,
    ExecutionStatus,
    PlannedStep,
)
from core.agents.registry import AgentRegistry
from core.graph.state import CaseInvestigationState

#: The Coordinator and Planning agents themselves are never valid plan
#: targets — they aren't registered as fan-out graph nodes
#: (`core/graph/investigation_graph.py`), so a capability collision with
#: their own declared capabilities ("coordination", "planning") must never
#: produce a step that routes to them. Kept as agent *names*, not
#: capability names, since a future specialist agent is free to declare a
#: capability literally named "planning" for its own domain purpose.
RESERVED_FRAMEWORK_AGENT_NAMES = frozenset({"coordinator", "planning_agent"})


class PlanningAgent(BaseAgent):
    """Builds an :class:`ExecutionPlan` from the capabilities declared on
    registered agents and the capability *signals* present on the case —
    dependency-aware sequencing and fan-out are the graph's job
    (`core/graph/routing.py`); this agent only decides *what* should run."""

    name: ClassVar[str] = "planning_agent"
    description: ClassVar[str] = (
        "Determines which registered agents a case's evidence requires, in "
        "what order, and which can run in parallel."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Match declared evidence-capability signals to registered agent capabilities.",
        "Sequence dependent agents; group independent agents for parallel execution.",
        "Fall back to a low-confidence, conservative plan when signals are ambiguous.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(name="planning", description="Builds execution plans for a case."),
    )

    def __init__(self, *, agent_registry: AgentRegistry) -> None:
        super().__init__()
        self._agent_registry = agent_registry

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        required_capabilities: list[str] = list(state.metadata.get("required_capabilities", []))

        if not required_capabilities:
            plan = ExecutionPlan(
                steps=(),
                termination_condition="no_capabilities_declared",
                confidence=ConfidenceScore.deterministic(
                    "No required capabilities declared on the case; nothing to plan."
                ),
            )
            state.execution_plan = plan
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.SUCCEEDED,
                thought="No evidence-capability signals present; produced an empty plan.",
                confidence=plan.confidence,
                output={"step_count": 0},
            )

        matched_steps: list[PlannedStep] = []
        unmatched: list[str] = []
        for capability in required_capabilities:
            candidates = [
                identity
                for identity in self._agent_registry.find_by_capability(capability)
                if identity.name not in RESERVED_FRAMEWORK_AGENT_NAMES
            ]
            if not candidates:
                unmatched.append(capability)
                continue
            # Deterministic tie-break: prefer the first registered candidate
            # by name, so plans are reproducible given the same registry.
            chosen = min(candidates, key=lambda identity: identity.name)
            matched_steps.append(
                PlannedStep(
                    agent_name=chosen.name,
                    rationale=f"Matched capability '{capability}'.",
                )
            )

        confidence = (
            ConfidenceScore.deterministic("Every required capability matched a registered agent.")
            if not unmatched
            else ConfidenceScore.llm_fallback(
                max(0.1, 1.0 - (len(unmatched) / len(required_capabilities))),
                rationale=f"Unmatched capabilities: {unmatched}",
            )
        )

        plan = ExecutionPlan(
            steps=tuple(matched_steps),
            termination_condition="all_steps_complete",
            confidence=confidence,
        )
        state.execution_plan = plan

        status = ExecutionStatus.SUCCEEDED if not unmatched else ExecutionStatus.DEGRADED
        thought = (
            f"Planned {len(matched_steps)} step(s) for capabilities {required_capabilities}."
            if not unmatched
            else (
                f"Planned {len(matched_steps)} step(s); no registered agent covers "
                f"{unmatched} — proceeding with a partial, lower-confidence plan."
            )
        )
        return AgentExecutionResult(
            agent_name=self.name,
            status=status,
            thought=thought,
            confidence=confidence,
            output={"step_count": len(matched_steps), "unmatched": unmatched},
        )
