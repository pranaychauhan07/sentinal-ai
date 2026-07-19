"""SOC Analyst Agent — blueprint §7: "the generalist log analyst —
summarizes events, flags anomalies, classifies severity."

Milestone M1's first concrete specialist agent. Reads `NormalizedEvidence`
items already on `CaseInvestigationState.evidence` (produced upstream by
`core/services/evidence_service.py`, before this agent ever runs) and, for
each, calls `core.tools.scoring.RiskScoringTool` to produce a `SocFinding` —
never computing the score itself (constitution §4.3/§4.11).

Scoping note (docs/adr/0014): `SocFinding` output is appended to
`CaseInvestigationState.findings` (the in-memory ReAct trail) and to this
agent's `AgentExecutionResult.output` — it is *not* written to the
persisted `findings` DB table, which remains the Finding & MITRE Engine's
(ADR-0013) exclusive, deterministic, IOC-driven output. Reconciling the two
into one shared, `source_agent`-tagged persisted Finding representation
(as blueprint §8's schema literally implies) is explicitly left to a future
milestone, not decided by default here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import NormalizedEvidence, Severity
from core.tools.registry import ToolRegistry
from core.tools.scoring import RiskScoringInput, RiskScoringOutput, RiskScoringTool

#: Event-type substrings that, combined with source concentration, suggest
#: a brute-force-shaped pattern (blueprint §7: "failed-login/brute-force
#: pattern detection"). Deliberately simple/deterministic — a real
#: signature/Sigma-rule engine is blueprint §16's flagged future work, not
#: this agent's job.
_FAILURE_SIGNAL_SUBSTRINGS: tuple[str, ...] = ("fail", "denied", "invalid", "reject")
#: Below this many repeated failure-shaped events from one source, the
#: agent does not flag suspected brute force at all (constitution §4.6:
#: "not found" must be distinguishable from "couldn't tell", not asserted
#: on a single event).
_BRUTE_FORCE_MIN_OCCURRENCES = 3


class SocFinding(BaseModel):
    """One evidence artifact's SOC-level summary — blueprint §7's
    `SocFinding[]`. Distinct from `core.findings.models.FindingRecord` (see
    module docstring)."""

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    source: str
    total_events: int
    severity_breakdown: dict[Severity, int]
    distinct_sources: int
    suspected_brute_force: bool
    risk_score: float
    risk_label: Severity
    summary: str


class SocAnalysisResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from (constitution §4.3: "a
    concrete agent should still validate/build it from a real Pydantic
    model internally")."""

    model_config = ConfigDict(frozen=True)

    findings: list[SocFinding] = Field(default_factory=list)
    skipped_non_evidence_items: int = 0


def default_soc_analyst_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `RiskScoringTool` registered — kept
    here (not in `core/graph`) because agents are already permitted to
    import `core/tools` directly (docs/dependency-rules.md rule 4); this is
    the one place `core/graph/investigation_graph.py`'s auto-registration
    helper needs to reach for to wire this agent up without itself
    constructing a concrete tool."""
    registry = ToolRegistry()
    registry.register(RiskScoringTool())
    return registry


def _brute_force_signal(evidence: NormalizedEvidence) -> bool:
    """Repeated failure-shaped events from a small number of sources.
    Requires both a minimum occurrence count and genuine source
    concentration — a single source failing once is not brute force."""
    failure_sources = Counter(
        record.ip_address or record.host
        for record in evidence.records
        if record.ip_address or record.host
        if record.event_type
        and any(sig in record.event_type.lower() for sig in _FAILURE_SIGNAL_SUBSTRINGS)
    )
    return any(count >= _BRUTE_FORCE_MIN_OCCURRENCES for count in failure_sources.values())


def _analyze_one(
    evidence: NormalizedEvidence, score: Callable[[RiskScoringInput], RiskScoringOutput]
) -> SocFinding:
    severity_counts: Counter[Severity] = Counter(record.severity for record in evidence.records)
    distinct_sources = len(
        {r.ip_address or r.host for r in evidence.records if r.ip_address or r.host}
    )

    scoring_output = score(
        RiskScoringInput(
            severity_counts=dict(severity_counts),
            total_events=evidence.record_count,
            distinct_sources=distinct_sources,
        )
    )
    suspected_brute_force = _brute_force_signal(evidence)

    summary = (
        f"{evidence.record_count} event(s) from '{evidence.source}' "
        f"({evidence.evidence_type.value}): risk={scoring_output.risk_label.value} "
        f"({scoring_output.risk_score:.1f}/100)"
        + (", suspected brute-force pattern" if suspected_brute_force else "")
        + "."
    )

    return SocFinding(
        evidence_id=evidence.evidence_id,
        source=evidence.source,
        total_events=evidence.record_count,
        severity_breakdown=dict(severity_counts),
        distinct_sources=distinct_sources,
        suspected_brute_force=suspected_brute_force,
        risk_score=scoring_output.risk_score,
        risk_label=scoring_output.risk_label,
        summary=summary,
    )


class SocAnalystAgent(BaseAgent):
    """Log summarization, brute-force pattern detection, severity
    classification (blueprint §7). Chunking/map-reduce for context-window
    overflow (blueprint §7's failure handling) does not apply here — this
    agent works from already-parsed `EvidenceRecord`s, never raw text, so
    there is no LLM context window in this path at all (constitution §1.9:
    deterministic where possible)."""

    name: ClassVar[str] = "soc_analyst"
    description: ClassVar[str] = (
        "Summarizes ingested evidence, classifies severity, and flags "
        "brute-force-shaped patterns using deterministic risk scoring."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Summarize each evidence artifact's event volume and severity distribution.",
        "Detect repeated-failure/brute-force-shaped patterns from source concentration.",
        "Classify overall risk via core.tools.scoring.RiskScoringTool.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="log_analysis", description="Analyzes normalized log/evidence artifacts."
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (RiskScoringTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        evidence_items: list[NormalizedEvidence] = []
        skipped = 0
        for item in state.evidence:
            if isinstance(item, NormalizedEvidence):
                evidence_items.append(item)
            else:
                skipped += 1

        if not evidence_items:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No NormalizedEvidence items present on case state; "
                    "insufficient evidence to analyze (not the same as 'no findings')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=SocAnalysisResult(skipped_non_evidence_items=skipped).model_dump(
                    mode="json"
                ),
            )

        def score(arguments: RiskScoringInput) -> RiskScoringOutput:
            result = self.use_tool(RiskScoringTool.name, arguments)
            assert isinstance(result, RiskScoringOutput)  # noqa: S101 - tool contract, not user input
            return result

        findings = [_analyze_one(evidence, score) for evidence in evidence_items]
        state.findings = [*state.findings, *findings]

        highest_risk = max((f.risk_score for f in findings), default=0.0)
        brute_force_count = sum(1 for f in findings if f.suspected_brute_force)
        thought = (
            f"Analyzed {len(findings)} evidence artifact(s); highest risk score "
            f"{highest_risk:.1f}/100; {brute_force_count} artifact(s) show suspected "
            f"brute-force patterns."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=SocAnalysisResult(
                findings=findings, skipped_non_evidence_items=skipped
            ).model_dump(mode="json"),
        )
