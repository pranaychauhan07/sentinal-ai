"""Linux Security Agent — blueprint §7: "command/permission advisor...
explain command, analyze permission strings, recommend hardening."

The fifth concrete specialist agent (`docs/roadmap.md`). Unlike
`ThreatHunterAgent` (ADR-0018's Linux-*log*-based detection), this agent
never parses a log, correlates events across time, or persists anything —
it reads the case's already-computed advisory data (produced by
`core.services.linux_advisor_service.assess_linux_command_input` *before*
this agent ever runs) — hydrated onto
`CaseInvestigationState.linux_advisory_records` by
`core/services/case_service.py` as plain `dict[str, object]` entries (not a
typed `core.linux_advisor.models.LinuxSecurityAdvice` import: `core/agents`
has no dependency-rules.md import edge onto `core/linux_advisor`, the
identical reasoning `core/agents/vulnerability_agent.py`'s docstring
documents for `core.vulnerabilities`) — and calls
`core.tools.linux_tools.LinuxSecurityAdvisoryTool` to produce a case-level
`LinuxSecurityAdvice` summary (blueprint's exact named output type). Never
re-analyzes a command, re-parses a permission string, or re-derives a risk
score itself (constitution §1.9).

Scoping note, matching `docs/adr/0014` point 4's precedent for
`SocFinding`/`PhishingVerdict`/`VulnerabilityAssessment`:
`LinuxSecurityAdvice` output is appended to `CaseInvestigationState.findings`
and this agent's `AgentExecutionResult.output` only — there is no persisted
`findings` DB row and no `Finding` table entry for it (this framework has no
DB persistence at all, per `docs/adr/0019`).
"""

from __future__ import annotations

from typing import ClassVar, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import EvidenceType, NormalizedEvidence
from core.tools.linux_tools import (
    LinuxCommandSummaryInput,
    LinuxHardeningSummaryInput,
    LinuxPermissionSummaryInput,
    LinuxSecurityAdvisoryInput,
    LinuxSecurityAdvisoryOutput,
    LinuxSecurityAdvisoryTool,
)
from core.tools.registry import ToolRegistry

#: Evidence types this agent's capability covers.
_LINUX_ADVISOR_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {EvidenceType.LINUX_COMMAND_INPUT}
)


class LinuxSecurityAdvice(BaseModel):
    """This case's Linux command/permission advisory verdict — blueprint
    §7's exact named output type."""

    model_config = ConfigDict(frozen=True)

    command_count: int = 0
    permission_count: int = 0
    flagged_command_count: int = 0
    flagged_permission_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    hardening_recommendation_count: int = 0
    baseline_recommendation_count: int = 0
    finding_triggered_recommendation_count: int = 0
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    top_command_findings: tuple[LinuxCommandSummaryInput, ...] = ()
    top_permission_findings: tuple[LinuxPermissionSummaryInput, ...] = ()


class LinuxSecurityAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    advice: LinuxSecurityAdvice | None = None
    skipped_non_command_items: int = 0


def default_linux_security_agent_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `LinuxSecurityAdvisoryTool`
    registered — mirrors `core.agents.vulnerability_agent.
    default_vulnerability_agent_tool_registry`'s shape exactly."""
    registry = ToolRegistry()
    registry.register(LinuxSecurityAdvisoryTool())
    return registry


def _records_by_kind(records: list[object], kind: str) -> list[dict[str, object]]:
    """Filters `CaseInvestigationState.linux_advisory_records` down to
    well-formed plain-dict entries of the given `kind`, skipping (never
    crashing on) anything else — the same "skip, don't crash" pattern
    `core.agents.vulnerability_agent._findings_from_state` uses."""
    matches: list[dict[str, object]] = []
    for item in records:
        if isinstance(item, dict) and item.get("kind") == kind:
            matches.append(item)
    return matches


class LinuxSecurityAgent(BaseAgent):
    """Aggregates the case's already-computed Linux command/permission
    advisory data into a case-level `LinuxSecurityAdvice` summary (blueprint
    §7). Never performs its own command tokenization, permission parsing,
    rule evaluation, or risk scoring — it consumes what
    `core.services.linux_advisor_service` already computed."""

    name: ClassVar[str] = "linux_security_agent"
    description: ClassVar[str] = (
        "Summarizes already-analyzed Linux command/permission advisory data "
        "for a case into an aggregate advice: severity counts, hardening "
        "recommendation counts, and the highest-severity findings."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Confirm Linux command/permission input evidence is present before summarizing.",
        "Aggregate already-analyzed command/permission risk data into a case-level advice.",
        "Never recompute a command's risk, a permission's risk, or the overall risk score itself.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="linux_security_advisory",
            description="Advises on Linux command/permission security and hardening.",
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (LinuxSecurityAdvisoryTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        command_items = 0
        skipped = 0
        for item in state.evidence:
            if not isinstance(item, NormalizedEvidence):
                continue
            if item.evidence_type in _LINUX_ADVISOR_EVIDENCE_TYPES:
                command_items += 1
            else:
                skipped += 1

        if command_items == 0:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No Linux command/permission input evidence present on case "
                    "state; insufficient evidence to advise (not the same as 'no "
                    "risky commands found')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=LinuxSecurityAgentResult(skipped_non_command_items=skipped).model_dump(
                    mode="json"
                ),
            )

        commands = _build_summaries(
            _records_by_kind(state.linux_advisory_records, "command"), LinuxCommandSummaryInput
        )
        permissions = _build_summaries(
            _records_by_kind(state.linux_advisory_records, "permission"),
            LinuxPermissionSummaryInput,
        )
        hardening = _build_summaries(
            _records_by_kind(state.linux_advisory_records, "hardening"), LinuxHardeningSummaryInput
        )
        summary_records = _records_by_kind(state.linux_advisory_records, "summary")
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
            LinuxSecurityAdvisoryTool.name,
            LinuxSecurityAdvisoryInput(
                commands=commands,
                permissions=permissions,
                hardening_recommendations=hardening,
                overall_risk_level=overall_risk_level,
                overall_confidence=overall_confidence,
                overall_explanation=overall_explanation,
                skipped_line_count=skipped_line_count,
            ),
        )
        assert isinstance(result, LinuxSecurityAdvisoryOutput)  # noqa: S101 - tool contract

        advice = LinuxSecurityAdvice(
            command_count=result.command_count,
            permission_count=result.permission_count,
            flagged_command_count=result.flagged_command_count,
            flagged_permission_count=result.flagged_permission_count,
            severity_counts=result.severity_counts,
            hardening_recommendation_count=result.hardening_recommendation_count,
            baseline_recommendation_count=result.baseline_recommendation_count,
            finding_triggered_recommendation_count=result.finding_triggered_recommendation_count,
            overall_risk_level=result.overall_risk_level,
            overall_confidence=result.overall_confidence,
            overall_explanation=result.overall_explanation,
            top_command_findings=result.top_command_findings,
            top_permission_findings=result.top_permission_findings,
        )
        state.findings = [*state.findings, advice]

        flagged_total = result.flagged_command_count + result.flagged_permission_count
        thought = (
            f"Advised on {result.command_count} command(s) and "
            f"{result.permission_count} permission entr(ies); {flagged_total} "
            f"flagged, overall risk '{result.overall_risk_level}'."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=LinuxSecurityAgentResult(
                advice=advice, skipped_non_command_items=skipped
            ).model_dump(mode="json"),
        )


_SummaryModelT = TypeVar("_SummaryModelT", bound=BaseModel)


def _build_summaries(
    records: list[dict[str, object]], model: type[_SummaryModelT]
) -> list[_SummaryModelT]:
    """Builds `model` instances from plain-dict `linux_advisory_records`
    entries, skipping (never crashing on) a malformed entry — the same
    "skip, don't crash" pattern `_records_by_kind` uses."""
    summaries: list[_SummaryModelT] = []
    for record in records:
        try:
            summaries.append(model(**{k: v for k, v in record.items() if k != "kind"}))
        except (TypeError, ValueError):
            continue
    return summaries
