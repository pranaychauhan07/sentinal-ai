"""Typed contracts shared by every concrete agent (`core/agents/*.py`) and,
one layer up, by the workflow engine that composes them
(`core/graph/workflow_engine.py`, `core/graph/routing.py`).

Nothing here is domain-specific (no cybersecurity concepts) — these are the
framework's own data shapes: who an agent is, what it was asked to do, how it
did, and how long it took. Per context/03_engineering_constitution.md §2,
every one of these is a Pydantic model, never a dict or a free-text stand-in.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.agents.confidence import ConfidenceScore


class ExecutionStatus(StrEnum):
    """Lifecycle status of one agent invocation
    (context/03_engineering_constitution.md §4.7/§9 — every failure mode is a
    typed, documented outcome, never an ambient "it just didn't work")."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"  # completed, but via a documented fallback path
    FAILED = "failed"
    SKIPPED = "skipped"  # never invoked (e.g. a dependency failed first)


class ExecutionMetadata(BaseModel):
    """Timing/outcome record for one agent invocation — the "Execution
    Metadata" every node in the workflow produces, independent of whatever
    domain result it also produced."""

    model_config = ConfigDict(frozen=True)

    agent_name: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime
    retry_count: int = 0
    error: str | None = None

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000


class AgentCapability(BaseModel):
    """One declared capability an agent offers — the unit the Planning Agent
    matches against signals present on the case (constitution §4.5: "which
    tools/capabilities an agent may use is declared explicitly", extended
    here to what work an agent can perform at all).

    Deliberately a free-form ``name`` (e.g. "log_analysis", "email_triage")
    rather than a closed enum: new specialist agents register new
    capabilities without editing a shared enum, which is exactly the
    "extend without modifying the framework" property this system is built
    for.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""


class AgentIdentity(BaseModel):
    """An agent's static self-description — what `BaseAgent.identity`
    exposes to the registry, the planner, and (eventually) the UI's agent
    catalog. Distinct from any single invocation's result."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    responsibilities: tuple[str, ...] = ()
    capabilities: tuple[AgentCapability, ...] = ()


class PlannedStep(BaseModel):
    """One entry in an :class:`ExecutionPlan` — which agent runs, what it
    depends on, and why the Planning Agent chose it."""

    model_config = ConfigDict(frozen=True)

    agent_name: str
    depends_on: tuple[str, ...] = ()
    parallel_group: str | None = None
    rationale: str = ""


class ExecutionPlan(BaseModel):
    """The Planning Agent's output (blueprint §7, "ExecutionGraph"): an
    ordered/dependency-aware set of agent invocations the Coordinator writes
    onto shared state for the graph's router to execute. The Coordinator
    never executes agents itself — it delegates *which* agents run to the
    Planning Agent and *how* they run (fan-out, sequencing) to the graph
    (`core/graph/routing.py`)."""

    steps: tuple[PlannedStep, ...] = ()
    fallback_agent: str | None = None
    termination_condition: str = "all_steps_complete"
    confidence: ConfidenceScore = Field(default_factory=ConfidenceScore.deterministic)

    @property
    def entry_steps(self) -> tuple[PlannedStep, ...]:
        """Steps with no unmet dependencies — what the router fans out to
        first."""
        return tuple(step for step in self.steps if not step.depends_on)

    @property
    def is_empty(self) -> bool:
        return len(self.steps) == 0


class AgentExecutionResult(BaseModel):
    """The full record of one agent's contribution to a case — what
    `BaseAgent.__call__` conceptually produces before the workflow engine
    folds it back into `CaseInvestigationState`. Kept generic (`output` is
    an opaque payload) because a concrete specialist agent's finding type
    (a `PhishingVerdict`, a `SocFinding[]`, ...) doesn't exist in this
    framework-only layer — see blueprint §7 for each agent's real output type
    once it's implemented."""

    agent_name: str
    status: ExecutionStatus
    thought: str
    confidence: ConfidenceScore
    output: dict[str, Any] = Field(default_factory=dict)
    metadata: ExecutionMetadata | None = None
