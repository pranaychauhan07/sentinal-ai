"""``CaseInvestigationState`` — the single typed object every LangGraph node
reads and writes during an investigation run.

Per context/03_engineering_constitution.md §4.2/§4.3, every field an agent
reads/writes is a typed Pydantic model. ``evidence``/``findings`` stay typed
as ``list[Any]`` for now, narrowed to concrete types (``NormalizedEvidence``,
``Finding``) once ``core/parsers`` and specialist agents introduce them
(Milestone M1) — narrowing that type is not an architecture change and does
not require a new ADR.

The multi-agent framework (Milestone M3, built ahead of schedule as pure
infrastructure per the roadmap note) adds the fields below the original M0
foundation: ``execution_plan`` (the Planning Agent's output the router
consumes), ``agent_outputs``/``confidence_scores``/``intermediate_results``
(keyed by agent name), ``execution_history``/``errors`` (the framework-level
execution trail — distinct from the future *persisted*
``TimelineEvent`` DB model, blueprint §8), and ``extensions`` (a namespaced
escape hatch for milestone-specific data before it graduates to a typed
field — not a general dumping ground; anything read by more than one agent
belongs in a real field, not here).

List/dict fields that specialist agents may write *concurrently* (a fan-out
of independent agents running in the same LangGraph superstep) are
``Annotated`` with a reducer (``operator.add`` for lists, ``_merge_dicts``
for dicts) so LangGraph merges concurrent writes instead of raising
``InvalidUpdateError`` — verified against langgraph's actual parallel-fanout
behavior before relying on it (see ``core/graph/workflow_engine.py``, which
is also what converts an agent's full-state return into the partial delta
these reducers expect).
"""

from __future__ import annotations

import operator
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from core.agents.contracts import AgentExecutionResult, ExecutionMetadata, ExecutionPlan


def _merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Reducer for dict-valued state fields multiple agents may write to in
    the same superstep. Assumes disjoint keys (each agent writes only its
    own name/entries) — LangGraph applies this pairwise across all writers
    in a superstep, so key collisions would silently prefer the
    later-applied write; agents only ever write their own ``agent_name`` key,
    which makes collisions structurally impossible in practice."""
    return {**left, **right}


class AgentThought(BaseModel):
    """One agent's ReAct reasoning entry — context/03_engineering_constitution.md
    §4.3 requires every agent output to include a human-readable ``thought``;
    this is the record of it kept on the shared state for the Investigation
    Trail UI (docs/user-guide.md)."""

    model_config = ConfigDict(frozen=True)

    agent_name: str
    thought: str
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now())


class ErrorRecord(BaseModel):
    """A structured, typed error entry on the shared state — never a bare
    string, so downstream consumers (UI, the Coordinator's failure-recovery
    decision) can filter/group by ``agent_name``/``code`` instead of parsing
    prose (constitution §9, "Validation errors ... never allowed to
    propagate as a generic ... unhandled exception")."""

    model_config = ConfigDict(frozen=True)

    agent_name: str
    code: str
    message: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now())


class CaseInvestigationState(BaseModel):
    """Shared state passed between every node in the Case Investigation Graph.

    No agent mutates data outside this object
    (context/03_engineering_constitution.md §3, §4.10) — this is the *only*
    channel data moves through during a graph run.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    case_id: UUID = Field(default_factory=uuid4)
    investigation_run_id: UUID = Field(default_factory=uuid4)

    #: Raw/normalized evidence attached to this run. Narrowed to
    #: ``list[NormalizedEvidence]`` once core/parsers exists (Milestone M1).
    evidence: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Typed findings produced by specialist agents so far. Narrowed to
    #: ``list[Finding]`` once core/agents produces concrete finding models.
    findings: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: IOCs (IPs, hashes, domains, ...) surfaced by any agent. Narrowed to a
    #: concrete ``Indicator`` model once the Threat Hunting Agent exists
    #: (Milestone M4) — kept generic here, this is framework infrastructure.
    extracted_indicators: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Full ReAct reasoning trail for this run, in chronological order.
    thoughts: Annotated[list[AgentThought], operator.add] = Field(default_factory=list)

    #: Structured, typed error entries (constitution §9) — distinct from
    #: ``thoughts``, which record reasoning, not failures.
    errors: Annotated[list[ErrorRecord], operator.add] = Field(default_factory=list)

    #: Chronological execution-metadata trail (one entry per agent
    #: invocation) — the framework's own timeline, not the persisted
    #: ``TimelineEvent`` domain model (blueprint §8, a future DB table).
    execution_history: Annotated[list[ExecutionMetadata], operator.add] = Field(
        default_factory=list
    )

    #: The Planning Agent's most recent output, written by the Coordinator
    #: and consumed by ``core/graph/routing.py`` to decide fan-out. Single
    #: writer (the Coordinator), so no concurrent-write reducer is needed.
    execution_plan: ExecutionPlan | None = None

    #: Each agent's full result, keyed by ``agent_name`` — what the
    #: Investigation Trail UI and the Report Generator Agent (Milestone M5)
    #: read instead of re-deriving findings from ``findings``/``thoughts``.
    agent_outputs: Annotated[dict[str, AgentExecutionResult], _merge_dicts] = Field(
        default_factory=dict
    )

    #: Confidence value per agent, mirrored out of ``agent_outputs`` for
    #: cheap lookup without walking the full result objects.
    confidence_scores: Annotated[dict[str, float], _merge_dicts] = Field(default_factory=dict)

    #: Scratch space for cross-agent intermediate values that aren't
    #: themselves a finding (e.g. a partially-built correlation candidate) —
    #: keyed by the writing agent's name, same concurrency contract as
    #: ``agent_outputs``.
    intermediate_results: Annotated[dict[str, Any], _merge_dicts] = Field(default_factory=dict)

    #: Case-level metadata evidence classification and the Planning Agent
    #: read from (e.g. declared evidence-type signals) — generic at this
    #: layer; concrete evidence classification is Milestone M1+.
    metadata: Annotated[dict[str, Any], _merge_dicts] = Field(default_factory=dict)

    #: Namespaced escape hatch for milestone-specific data before it
    #: graduates to a typed field. Not a general-purpose dumping ground
    #: (constitution §2, "no misc helpers module") — data read by more than
    #: one agent belongs in a real, named field instead.
    extensions: Annotated[dict[str, Any], _merge_dicts] = Field(default_factory=dict)

    #: Set by the Coordinator when evidence classification fails, or by
    #: failure-recovery when an agent exhausts retries with no safe
    #: fallback — see context/01_blueprint.md §7 (Coordinator Agent,
    #: Failure handling).
    requires_manual_triage: bool = False

    def add_thought(self, agent_name: str, thought: str, confidence: float) -> None:
        """Append a reasoning entry. The one sanctioned way to record an
        agent's Thought — never append to ``self.thoughts`` directly, so
        every entry is guaranteed well-formed."""
        self.thoughts.append(
            AgentThought(agent_name=agent_name, thought=thought, confidence=confidence)
        )

    def add_error(self, agent_name: str, code: str, message: str) -> None:
        """Append a structured error entry — the sanctioned counterpart to
        :meth:`add_thought` for failures."""
        self.errors.append(ErrorRecord(agent_name=agent_name, code=code, message=message))
