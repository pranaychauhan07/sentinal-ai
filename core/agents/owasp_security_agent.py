"""OWASP Security Agent — blueprint §7's source-code/API static reviewer
(`docs/adr/0021-owasp-security-agent-ast-sast.md`).

The seventh concrete specialist agent (`docs/roadmap.md`) — closes M4
entirely. This agent never parses source code, builds an AST, evaluates a
rule, or computes a risk score itself — it reads the case's already-computed
SAST data (produced by
`core.services.owasp_security_service.assess_source_code` *before* this
agent ever runs) — hydrated onto
`CaseInvestigationState.owasp_security_records` by
`core/services/case_service.py` as plain `dict[str, object]` entries (not a
typed `core.owasp_security.models.SastAdvice` import: `core/agents` has no
dependency-rules.md import edge onto `core/owasp_security`, the identical
reasoning `core/agents/web_security_agent.py`'s docstring documents) — and
calls `core.tools.owasp_tools.OwaspSecurityAssessmentTool` to produce a
case-level `SastAdvice` summary. Never re-analyzes a source file or
re-derives a risk score itself (constitution §1.9).

Scoping note, matching `docs/adr/0019`/`docs/adr/0020`'s precedent:
`SastAdvice` output is appended to `CaseInvestigationState.findings` and this
agent's `AgentExecutionResult.output` only — there is no persisted `findings`
DB row and no `Finding` table entry for it (this framework has no DB
persistence at all, per `docs/adr/0021`).

**Not** `core/agents/web_security_agent.py` (ADR-0020's HTTP-traffic
analyzer, no source code, no AST) — see the ADR for why these are
deliberately separate.
"""

from __future__ import annotations

from typing import ClassVar, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import EvidenceType, NormalizedEvidence
from core.tools.owasp_tools import (
    OwaspSecurityAssessmentInput,
    OwaspSecurityAssessmentOutput,
    OwaspSecurityAssessmentTool,
    SastFindingSummaryInput,
)
from core.tools.registry import ToolRegistry

#: Evidence types this agent's capability covers.
_OWASP_SECURITY_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset({EvidenceType.SOURCE_CODE})


class SastAdvice(BaseModel):
    """This case's AST/pattern-based SAST advisory verdict."""

    model_config = ConfigDict(frozen=True)

    language: str = "unknown"
    finding_count: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    cwe_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    parse_degraded: bool = False
    top_findings: tuple[SastFindingSummaryInput, ...] = ()


class OwaspSecurityAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    advice: SastAdvice | None = None
    skipped_non_source_items: int = 0


def default_owasp_security_agent_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `OwaspSecurityAssessmentTool`
    registered — mirrors `core.agents.web_security_agent.
    default_web_security_agent_tool_registry`'s shape exactly."""
    registry = ToolRegistry()
    registry.register(OwaspSecurityAssessmentTool())
    return registry


def _records_by_kind(records: list[object], kind: str) -> list[dict[str, object]]:
    """Filters `CaseInvestigationState.owasp_security_records` down to
    well-formed plain-dict entries of the given `kind`, skipping (never
    crashing on) anything else — the same "skip, don't crash" pattern
    `core.agents.web_security_agent._records_by_kind` uses."""
    matches: list[dict[str, object]] = []
    for item in records:
        if isinstance(item, dict) and item.get("kind") == kind:
            matches.append(item)
    return matches


class OwaspSecurityAgent(BaseAgent):
    """Aggregates the case's already-computed AST/pattern-based SAST
    advisory data into a case-level `SastAdvice` summary. Never performs its
    own source parsing, AST building, rule evaluation, or risk scoring — it
    consumes what `core.services.owasp_security_service` already computed."""

    name: ClassVar[str] = "owasp_security_agent"
    description: ClassVar[str] = (
        "Summarizes already-analyzed AST/pattern-based SAST advisory data "
        "for a case into an aggregate advice: OWASP category/CWE/severity "
        "counts and the highest-severity findings."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Confirm source code evidence is present before summarizing.",
        "Aggregate already-analyzed SAST finding data into a case-level advice.",
        "Never recompute a finding's severity, confidence, or the overall risk score itself.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="owasp_source_code_review",
            description=(
                "Reviews source code for OWASP Top 10-mapped vulnerabilities via "
                "AST/pattern analysis."
            ),
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (OwaspSecurityAssessmentTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        source_items = 0
        skipped = 0
        for item in state.evidence:
            if not isinstance(item, NormalizedEvidence):
                continue
            if item.evidence_type in _OWASP_SECURITY_EVIDENCE_TYPES:
                source_items += 1
            else:
                skipped += 1

        if source_items == 0:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No source code evidence present on case state; insufficient "
                    "evidence to review (not the same as 'no vulnerabilities found')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=OwaspSecurityAgentResult(skipped_non_source_items=skipped).model_dump(
                    mode="json"
                ),
            )

        findings = _build_summaries(
            _records_by_kind(state.owasp_security_records, "finding"), SastFindingSummaryInput
        )
        summary_records = _records_by_kind(state.owasp_security_records, "summary")
        language = "unknown"
        overall_risk_level = "info"
        overall_confidence = 1.0
        overall_explanation = ""
        parse_degraded = False
        if summary_records:
            latest = summary_records[-1]
            language = str(latest.get("language", "unknown"))
            overall_risk_level = str(latest.get("overall_risk_level", "info"))
            overall_confidence = float(latest.get("overall_confidence", 1.0))  # type: ignore[arg-type]
            overall_explanation = str(latest.get("overall_explanation", ""))
            parse_degraded = bool(latest.get("parse_degraded", False))

        result = self.use_tool(
            OwaspSecurityAssessmentTool.name,
            OwaspSecurityAssessmentInput(
                language=language,
                findings=findings,
                overall_risk_level=overall_risk_level,
                overall_confidence=overall_confidence,
                overall_explanation=overall_explanation,
                parse_degraded=parse_degraded,
            ),
        )
        assert isinstance(result, OwaspSecurityAssessmentOutput)  # noqa: S101 - tool contract

        advice = SastAdvice(
            language=result.language,
            finding_count=result.finding_count,
            category_counts=result.category_counts,
            cwe_counts=result.cwe_counts,
            severity_counts=result.severity_counts,
            overall_risk_level=result.overall_risk_level,
            overall_confidence=result.overall_confidence,
            overall_explanation=result.overall_explanation,
            parse_degraded=result.parse_degraded,
            top_findings=result.top_findings,
        )
        state.findings = [*state.findings, advice]

        thought = (
            f"Reviewed {language} source: {result.finding_count} SAST finding(s) across "
            f"{len(result.category_counts)} categor(y/ies); overall risk "
            f"'{result.overall_risk_level}'."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=OwaspSecurityAgentResult(
                advice=advice, skipped_non_source_items=skipped
            ).model_dump(mode="json"),
        )


_SummaryModelT = TypeVar("_SummaryModelT", bound=BaseModel)


def _build_summaries(
    records: list[dict[str, object]], model: type[_SummaryModelT]
) -> list[_SummaryModelT]:
    """Builds `model` instances from plain-dict `owasp_security_records`
    entries, skipping (never crashing on) a malformed entry — the same
    "skip, don't crash" pattern `_records_by_kind` uses."""
    summaries: list[_SummaryModelT] = []
    for record in records:
        try:
            summaries.append(model(**{k: v for k, v in record.items() if k != "kind"}))
        except (TypeError, ValueError):
            continue
    return summaries
