"""MITRE Mapping Agent — blueprint §7's cross-cutting technique mapper.

Blueprint's exact scope: "map a described behavior... to MITRE technique
ID... with tactic/phase... Failure handling: returns 'unmapped' rather than
forcing a low-confidence guess into the report." This agent never computes
a technique mapping or its confidence itself — that is entirely
`core.findings.mapping_engine.MitreMappingEngine`'s job, already run by
`core.services.finding_service.generate_findings_for_case` for every case
before this agent ever executes (docs/adr/0013-finding-mitre-intelligence-
engine-shape.md). This agent's own job is narrower: read the case's
already-computed technique mappings (hydrated onto
`CaseInvestigationState.mitre_mapping_records` by
`core/services/case_service.py` from the case's persisted `Finding` rows)
and resolve/aggregate them — tactic phases, sub-technique parents,
associated threat groups, associated software, and mitigations — via
`core.tools.mitre_tools.MitreMappingResolutionTool`, into one case-level
summary.

Unlike every other specialist agent in this codebase
(`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`, `LinuxSecurityAgent`,
`WebSecurityAgent`, `OwaspSecurityAgent`), this agent is explicitly
permitted to import `core.knowledge.mitre` directly
(docs/dependency-rules.md rule 4, "core/agents may import ... core/knowledge",
rule 4c) — MITRE reference data is shared knowledge-layer data, not a
sibling leaf's private model, and this agent exists specifically to resolve
against it. `mitre_mapping_records` itself still stays dict-shaped on
`CaseInvestigationState`, matching every other `*_records` field's
precedent (`core/graph/state.py`'s fields are uniformly `list[Any]`;
`core/graph` — unlike `core/agents` — has no documented import edge onto
`core/knowledge`/`core/findings`).

This agent is cross-cutting, not evidence-type-gated:
`core/services/case_service.py._required_capabilities_for` appends its
capability to *every* evidence type's required-capability list, since
Finding generation (and therefore MITRE mapping) already runs
unconditionally on every evidence upload (blueprint §9 step 7 runs
immediately after step 6, regardless of evidence type). A case with no
mapped technique yet (no matching IOC, or every candidate mapping fell
below `Settings.finding_mapping_min_confidence`) is not an error — this
agent returns a `DEGRADED`, zero-technique "unmapped" result rather than
forcing a low-confidence guess, exactly as blueprint §7 specifies.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.config import Settings
from core.graph.state import CaseInvestigationState
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.knowledge.mitre.lookup import MitreLookup
from core.tools.mitre_tools import (
    MitreCaseMappingInput,
    MitreCaseMappingOutput,
    MitreMappingResolutionTool,
    MitreTechniqueMappingInput,
    MitreTechniqueResolution,
)
from core.tools.registry import ToolRegistry


class MitreCaseMappingSummary(BaseModel):
    """This case's resolved ATT&CK technique/tactic/group/software/
    mitigation coverage — what `AgentExecutionResult.output` is built
    from."""

    model_config = ConfigDict(frozen=True)

    technique_count: int = 0
    tactic_coverage: dict[str, int] = Field(default_factory=dict)
    distinct_group_count: int = 0
    distinct_software_count: int = 0
    unresolved_technique_ids: tuple[str, ...] = ()
    top_techniques: tuple[MitreTechniqueResolution, ...] = ()


class MitreMappingAgentResult(BaseModel):
    """This agent's full output payload."""

    model_config = ConfigDict(frozen=True)

    summary: MitreCaseMappingSummary | None = None
    skipped_malformed_record_count: int = 0


def default_mitre_mapping_agent_tool_registry(*, settings: Settings) -> ToolRegistry:
    """Constructs a `ToolRegistry` with `MitreMappingResolutionTool`
    registered, injected with a `MitreLookup` built from `settings` — the
    one agent factory in this codebase that needs a `Settings` parameter,
    since its tool's dependency (a loaded `MitreDataset`) isn't a
    no-argument construction like every sibling specialist agent's tool
    registry (constitution §2, "Dependency injection ... as constructor/
    function parameters, not by importing a global singleton")."""
    lookup = MitreLookup(load_mitre_dataset(settings))
    registry = ToolRegistry()
    registry.register(MitreMappingResolutionTool(lookup=lookup))
    return registry


def _valid_mapping_records(
    records: list[object],
) -> tuple[list[MitreTechniqueMappingInput], int]:
    """Builds `MitreTechniqueMappingInput`s from plain-dict
    `mitre_mapping_records` entries, skipping (never crashing on) a
    malformed entry — the same "skip, don't crash" pattern every other
    specialist agent's record-parsing helper uses (e.g.
    `core.agents.owasp_security_agent._records_by_kind`)."""
    valid: list[MitreTechniqueMappingInput] = []
    skipped = 0
    for item in records:
        if not isinstance(item, dict) or "technique_id" not in item:
            skipped += 1
            continue
        try:
            valid.append(
                MitreTechniqueMappingInput(
                    technique_id=str(item["technique_id"]),
                    tactic_ids=tuple(item.get("tactic_ids") or ()),
                    confidence=float(item.get("confidence", 0.0)),  # type: ignore[arg-type]
                    mapping_source=str(item.get("mapping_source", "")),
                    finding_id=str(item.get("finding_id", "")),
                )
            )
        except (TypeError, ValueError):
            skipped += 1
    return valid, skipped


class MitreMappingAgent(BaseAgent):
    """Resolves and aggregates a case's already-computed technique mappings
    into a case-level ATT&CK coverage summary. Never computes a technique
    mapping, a confidence value, or a tactic assignment itself — those are
    `core.findings.mapping_engine.MitreMappingEngine`'s job, already run
    before this agent ever executes."""

    name: ClassVar[str] = "mitre_mapping_agent"
    description: ClassVar[str] = (
        "Resolves a case's already-mapped ATT&CK techniques to their tactics, "
        "sub-technique parents, associated threat groups, software, and "
        "mitigations, and aggregates them into a case-level coverage summary."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Confirm at least one already-computed technique mapping is present.",
        "Resolve tactic/group/software/mitigation metadata for each mapped technique.",
        "Never recompute a technique mapping or its confidence itself.",
        "Return an 'unmapped' degraded result rather than a low-confidence guess.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="mitre_technique_mapping",
            description="Resolves and aggregates a case's ATT&CK technique mappings.",
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (MitreMappingResolutionTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        mappings, skipped = _valid_mapping_records(state.mitre_mapping_records)

        if not mappings:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No already-mapped ATT&CK technique present for this case; "
                    "returning unmapped rather than forcing a low-confidence guess."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=MitreMappingAgentResult(skipped_malformed_record_count=skipped).model_dump(
                    mode="json"
                ),
            )

        result = self.use_tool(
            MitreMappingResolutionTool.name,
            MitreCaseMappingInput(mappings=mappings),
        )
        assert isinstance(result, MitreCaseMappingOutput)  # noqa: S101 - tool contract

        summary = MitreCaseMappingSummary(
            technique_count=result.technique_count,
            tactic_coverage=result.tactic_coverage,
            distinct_group_count=result.distinct_group_count,
            distinct_software_count=result.distinct_software_count,
            unresolved_technique_ids=result.unresolved_technique_ids,
            top_techniques=result.top_techniques,
        )
        state.findings = [*state.findings, summary]

        thought = (
            f"Resolved {result.technique_count} mapped ATT&CK technique(s) across "
            f"{len(result.tactic_coverage)} tactic(s); {result.distinct_group_count} "
            f"threat group(s) and {result.distinct_software_count} software entr(ies) "
            "associated."
        )
        if result.unresolved_technique_ids:
            thought += (
                f" {len(result.unresolved_technique_ids)} technique ID(s) could not be "
                "resolved against the loaded MITRE dataset."
            )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=MitreMappingAgentResult(
                summary=summary, skipped_malformed_record_count=skipped
            ).model_dump(mode="json"),
        )
