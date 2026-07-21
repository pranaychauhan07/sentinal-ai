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

    #: Already-generated `core.vulnerabilities.models.VulnerabilityFinding`
    #: data (hydrated as plain ``dict[str, object]`` entries by
    #: `core/services/case_service.py` from
    #: `core.services.vulnerability_service.assess_vulnerabilities()`'s
    #: result) for `core.agents.vulnerability_agent.VulnerabilityAssessmentAgent`
    #: to summarize. Kept generic (``list[Any]``) for the same reason
    #: ``extracted_indicators`` is: `core/agents` has no dependency-rules.md
    #: import edge onto `core/vulnerabilities`, so this field is never a
    #: typed `VulnerabilityFinding` list.
    vulnerability_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Already-generated `core.linux_security.models.LinuxSecurityFinding`
    #: data (hydrated as plain ``dict[str, object]`` entries by
    #: `core/services/case_service.py` from
    #: `core.services.linux_security_service.assess_linux_security()`'s
    #: result) for `core.agents.threat_hunter_agent.ThreatHunterAgent` to
    #: summarize. Kept generic (``list[Any]``) for the same reason
    #: ``vulnerability_records`` is: `core/agents` has no dependency-rules.md
    #: import edge onto `core/linux_security`, so this field is never a
    #: typed `LinuxSecurityFinding` list.
    linux_security_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Already-computed Linux command/permission advisory data (hydrated as
    #: plain ``dict[str, object]`` entries by
    #: `core/services/case_service.py` from
    #: `core.services.linux_advisor_service.assess_linux_command_input()`'s
    #: result) for `core.agents.linux_security_agent.LinuxSecurityAgent` to
    #: summarize. Deliberately a **different** field name from
    #: ``linux_security_records`` (which `ThreatHunterAgent` already uses) to
    #: avoid any collision between ADR-0018's Linux Security *Threat
    #: Hunting* Framework and ADR-0019's Linux Security *Advisor* Framework
    #: — two separate packages that must never be confused. Kept generic
    #: (``list[Any]``) for the same reason ``vulnerability_records`` is:
    #: `core/agents` has no dependency-rules.md import edge onto
    #: `core/linux_advisor`, so this field is never a typed
    #: `LinuxSecurityAdvice` list.
    linux_advisory_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Already-computed OWASP-mapped HTTP security advisory data (hydrated as
    #: plain ``dict[str, object]`` entries by
    #: `core/services/case_service.py` from
    #: `core.services.web_security_service.assess_http_transaction()`'s
    #: result) for `core.agents.web_security_agent.WebSecurityAgent` to
    #: summarize. Deliberately a **different** field name from every other
    #: ``*_records`` field — a new, distinct framework
    #: (`docs/adr/0020-owasp-web-security-agent.md`) that must never be
    #: confused with any prior one. Kept generic (``list[Any]``) for the same
    #: reason ``linux_advisory_records`` is: `core/agents` has no
    #: dependency-rules.md import edge onto `core/owasp_web`, so this field
    #: is never a typed `WebSecurityAdvice` list.
    owasp_web_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Already-computed AST/pattern-based SAST advisory data (hydrated as
    #: plain ``dict[str, object]`` entries by
    #: `core/services/case_service.py` from
    #: `core.services.owasp_security_service.assess_source_code()`'s
    #: result) for `core.agents.owasp_security_agent.OwaspSecurityAgent` to
    #: summarize. Deliberately a **different** field name from every other
    #: ``*_records`` field — a new, distinct framework
    #: (`docs/adr/0021-owasp-security-agent-ast-sast.md`) that must never be
    #: confused with `owasp_web_records` (ADR-0020's HTTP-traffic analyzer).
    #: Kept generic (``list[Any]``) for the same reason ``owasp_web_records``
    #: is: `core/agents` has no dependency-rules.md import edge onto
    #: `core/owasp_security`, so this field is never a typed `SastAdvice`
    #: list.
    owasp_security_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: Already-computed `core.findings.models.MitreMapping` data (hydrated as
    #: plain ``dict[str, object]`` entries by `core/services/case_service.py`
    #: from the case's persisted `Finding.mitre_mappings`, produced by
    #: `core.services.finding_service.generate_findings_for_case()` — never
    #: recomputed here) for
    #: `core.agents.mitre_mapping_agent.MitreMappingAgent` to resolve/
    #: aggregate. Kept generic (``list[Any]``) for the same uniform reason
    #: every other ``*_records`` field is, even though `core/agents` is
    #: explicitly permitted to import `core.findings`/`core.knowledge`
    #: directly for MITRE mapping (docs/dependency-rules.md rule 4c) —
    #: `core/graph` (this module) has no such exception, so the field itself
    #: stays generic.
    mitre_mapping_records: Annotated[list[Any], operator.add] = Field(default_factory=list)

    #: This case's already-persisted `Finding` rows (SOC Analyst / Threat
    #: Hunting / Phishing-derived, case-wide across every prior upload),
    #: reduced to plain `dict[str, object]` entries by
    #: `core/services/case_service.py::_hydrate_incident_response_records`
    #: for `core.agents.incident_response_agent.IncidentResponseAgent` to
    #: normalize into `core.incident_response.inputs.IncidentInputFinding`.
    #: Deliberately a **different** field name from every other
    #: ``*_records`` field — this one is case-wide (mirrors
    #: ``mitre_mapping_records``'s scope), while
    #: ``vulnerability_records``/``linux_security_records``/
    #: ``linux_advisory_records``/``owasp_web_records``/
    #: ``owasp_security_records`` are scoped to the current upload only
    #: (docs/adr/0023-incident-response-agent.md, Decision 1). Kept generic
    #: (``list[Any]``) for the same reason ``mitre_mapping_records`` is:
    #: `core/graph` has no dependency-rules.md import edge onto
    #: `core/incident_response`, so this field is never a typed
    #: `IncidentInputFinding` list.
    incident_response_finding_records: Annotated[list[Any], operator.add] = Field(
        default_factory=list
    )

    #: This case's most recently *persisted* `IncidentResponsePlan` (a plain
    #: `dict[str, object]`, `json.loads`'d from `IncidentResponsePlanRow.
    #: plan_data_json` by `core/services/case_service.py::
    #: _hydrate_incident_response_plan_record`), for
    #: `core.agents.report_generator_agent.ReportGeneratorAgent`'s Incident
    #: Response Actions section. `None` if no plan has ever been persisted
    #: for this case yet. Deliberately one run behind this run's own
    #: `IncidentResponseAgent` output (docs/adr/0024-report-generator-agent.md,
    #: Decision 2) — hydration happens before `engine.run(state)`, while
    #: `IncidentResponsePlanRepository.upsert_for_case` for *this* run's plan
    #: happens after the graph completes. Single writer (`case_service.py`,
    #: before the run), so — like ``execution_plan`` — no concurrent-write
    #: reducer is needed.
    incident_response_plan_record: dict[str, Any] | None = None

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
