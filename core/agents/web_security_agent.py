"""Web Security Agent — a deterministic OWASP-mapped analyzer of HTTP
traffic artifacts (`docs/adr/0020-owasp-web-security-agent.md`).

The sixth concrete specialist agent (`docs/roadmap.md`). This agent never
parses a header/cookie/JWT, evaluates a rule, or computes a risk score
itself — it reads the case's already-computed advisory data (produced by
`core.services.web_security_service.assess_http_transaction` *before* this
agent ever runs) — hydrated onto
`CaseInvestigationState.owasp_web_records` by `core/services/case_service.py`
as plain `dict[str, object]` entries (not a typed
`core.owasp_web.models.WebSecurityAdvice` import: `core/agents` has no
dependency-rules.md import edge onto `core/owasp_web`, the identical
reasoning `core/agents/linux_security_agent.py`'s docstring documents for
`core.linux_advisor`) — and calls
`core.tools.web_security_tools.WebSecurityAdvisoryTool` to produce a
case-level `WebSecurityAdvice` summary. Never re-analyzes a header, cookie,
or JWT, or re-derives a risk score itself (constitution §1.9).

Scoping note, matching `docs/adr/0019` point 3's precedent: `WebSecurityAdvice`
output is appended to `CaseInvestigationState.findings` and this agent's
`AgentExecutionResult.output` only — there is no persisted `findings` DB row
and no `Finding` table entry for it (this framework has no DB persistence at
all, per `docs/adr/0020`).

**Not** blueprint §7's OWASP Security Agent (AST-based source-code/API
static review, still unbuilt) — see `docs/adr/0020` for why these are
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
from core.tools.registry import ToolRegistry
from core.tools.web_security_tools import (
    OwaspFindingSummaryInput,
    WebSecurityAdvisoryInput,
    WebSecurityAdvisoryOutput,
    WebSecurityAdvisoryTool,
)

#: Evidence types this agent's capability covers.
_WEB_SECURITY_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset({EvidenceType.HTTP_TRANSACTION})


class WebSecurityAdvice(BaseModel):
    """This case's OWASP-mapped web security advisory verdict."""

    model_config = ConfigDict(frozen=True)

    finding_count: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    skipped_line_count: int = 0
    top_findings: tuple[OwaspFindingSummaryInput, ...] = ()


class WebSecurityAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    advice: WebSecurityAdvice | None = None
    skipped_non_http_items: int = 0


def default_web_security_agent_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `WebSecurityAdvisoryTool` registered
    — mirrors `core.agents.linux_security_agent.
    default_linux_security_agent_tool_registry`'s shape exactly."""
    registry = ToolRegistry()
    registry.register(WebSecurityAdvisoryTool())
    return registry


def _records_by_kind(records: list[object], kind: str) -> list[dict[str, object]]:
    """Filters `CaseInvestigationState.owasp_web_records` down to well-formed
    plain-dict entries of the given `kind`, skipping (never crashing on)
    anything else — the same "skip, don't crash" pattern
    `core.agents.linux_security_agent._records_by_kind` uses."""
    matches: list[dict[str, object]] = []
    for item in records:
        if isinstance(item, dict) and item.get("kind") == kind:
            matches.append(item)
    return matches


class WebSecurityAgent(BaseAgent):
    """Aggregates the case's already-computed OWASP-mapped HTTP security
    advisory data into a case-level `WebSecurityAdvice` summary. Never
    performs its own header/cookie/JWT analysis, rule evaluation, or risk
    scoring — it consumes what `core.services.web_security_service` already
    computed."""

    name: ClassVar[str] = "web_security_agent"
    description: ClassVar[str] = (
        "Summarizes already-analyzed OWASP-mapped HTTP security advisory "
        "data for a case into an aggregate advice: category/severity "
        "counts and the highest-severity findings."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Confirm HTTP transaction evidence is present before summarizing.",
        "Aggregate already-analyzed header/cookie/JWT/misconfiguration risk data "
        "into a case-level advice.",
        "Never recompute a header's, cookie's, or JWT's risk, or the overall risk score itself.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="owasp_web_security_assessment",
            description="Advises on OWASP-mapped HTTP traffic security issues.",
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (WebSecurityAdvisoryTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        http_items = 0
        skipped = 0
        for item in state.evidence:
            if not isinstance(item, NormalizedEvidence):
                continue
            if item.evidence_type in _WEB_SECURITY_EVIDENCE_TYPES:
                http_items += 1
            else:
                skipped += 1

        if http_items == 0:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No HTTP transaction evidence present on case state; "
                    "insufficient evidence to advise (not the same as 'no web "
                    "security issues found')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=WebSecurityAgentResult(skipped_non_http_items=skipped).model_dump(
                    mode="json"
                ),
            )

        findings = _build_summaries(
            _records_by_kind(state.owasp_web_records, "finding"), OwaspFindingSummaryInput
        )
        summary_records = _records_by_kind(state.owasp_web_records, "summary")
        overall_risk_level = "info"
        overall_confidence = 1.0
        overall_explanation = ""
        skipped_line_count = 0
        if summary_records:
            latest = summary_records[-1]
            overall_risk_level = str(latest.get("overall_risk_level", "info"))
            overall_confidence = float(latest.get("overall_confidence", 1.0))  # type: ignore[arg-type]
            overall_explanation = str(latest.get("overall_explanation", ""))
            skipped_line_count = int(latest.get("skipped_line_count", 0))  # type: ignore[call-overload]

        result = self.use_tool(
            WebSecurityAdvisoryTool.name,
            WebSecurityAdvisoryInput(
                findings=findings,
                overall_risk_level=overall_risk_level,
                overall_confidence=overall_confidence,
                overall_explanation=overall_explanation,
                skipped_line_count=skipped_line_count,
            ),
        )
        assert isinstance(result, WebSecurityAdvisoryOutput)  # noqa: S101 - tool contract

        advice = WebSecurityAdvice(
            finding_count=result.finding_count,
            category_counts=result.category_counts,
            severity_counts=result.severity_counts,
            overall_risk_level=result.overall_risk_level,
            overall_confidence=result.overall_confidence,
            overall_explanation=result.overall_explanation,
            skipped_line_count=result.skipped_line_count,
            top_findings=result.top_findings,
        )
        state.findings = [*state.findings, advice]

        thought = (
            f"Advised on {result.finding_count} OWASP-mapped finding(s) across "
            f"{len(result.category_counts)} categor(y/ies); overall risk "
            f"'{result.overall_risk_level}'."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=WebSecurityAgentResult(advice=advice, skipped_non_http_items=skipped).model_dump(
                mode="json"
            ),
        )


_SummaryModelT = TypeVar("_SummaryModelT", bound=BaseModel)


def _build_summaries(
    records: list[dict[str, object]], model: type[_SummaryModelT]
) -> list[_SummaryModelT]:
    """Builds `model` instances from plain-dict `owasp_web_records` entries,
    skipping (never crashing on) a malformed entry — the same "skip, don't
    crash" pattern `_records_by_kind` uses."""
    summaries: list[_SummaryModelT] = []
    for record in records:
        try:
            summaries.append(model(**{k: v for k, v in record.items() if k != "kind"}))
        except (TypeError, ValueError):
            continue
    return summaries
