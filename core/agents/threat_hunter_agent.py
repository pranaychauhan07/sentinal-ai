"""Threat Hunting Agent — blueprint §7: "proactive IOC hunting across
firewall/IDS/server logs... identify multi-stage patterns (recon ->
exploitation -> persistence)."

This session's concrete deliverable is the Linux-log-based detection
surface: `core.linux_security` (SSH brute force / compromise-after-brute-
force / sudo abuse / privilege escalation / persistence / suspicious
process detection over `SSH_AUTH`/`SYSLOG` evidence). Broader firewall/IDS
multi-stage IOC narrative-hunting beyond what `core.threat_intel`'s existing
IOC extraction already provides remains future work — this agent does not
re-implement or duplicate `core.threat_intel`'s IOC extraction; it adds a
second, Linux-log-specific detection dimension the Coordinator now fans out
to for `SSH_AUTH`/`SYSLOG` evidence, alongside `SocAnalystAgent`.

Like `VulnerabilityAssessmentAgent`, this agent does not itself run
detection/scoring/finding generation — all of that already happened in
`core.services.linux_security_service.LinuxSecurityPipeline` *before* this
agent ever runs. This agent is deliberately thin: it reads the case's
already-generated `LinuxSecurityFinding`s — hydrated onto
`CaseInvestigationState.linux_security_records` by
`core/services/case_service.py` as plain `dict[str, object]` entries (not a
typed `core.linux_security.models.LinuxSecurityFinding` import: `core/agents`
has no dependency-rules.md import edge onto `core/linux_security`, the
identical reasoning `core/agents/vulnerability_agent.py`'s docstring
documents for `core.vulnerabilities`) — and calls
`core.tools.linux_security_tools.LinuxSecurityAssessmentTool` to produce a
case-level `ThreatHuntingReport`. Never re-extracts, re-scores, or
re-prioritizes a finding itself (constitution §1.9).

Scoping note, matching `docs/adr/0014` point 4's precedent for
`SocFinding`/`PhishingVerdict`/`VulnerabilityAssessment`: `ThreatHuntingReport`
output is appended to `CaseInvestigationState.findings` and this agent's
`AgentExecutionResult.output` only — it is not written to the persisted
`findings` DB table.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import EvidenceType, NormalizedEvidence
from core.tools.linux_security_tools import (
    LinuxSecurityAssessmentInput,
    LinuxSecurityAssessmentOutput,
    LinuxSecurityAssessmentTool,
    LinuxSecurityFindingSummaryInput,
)
from core.tools.registry import ToolRegistry

#: Evidence types this agent's capability covers.
_THREAT_HUNTING_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {EvidenceType.SSH_AUTH, EvidenceType.SYSLOG}
)


class ThreatHuntingReport(BaseModel):
    """This case's threat-hunting verdict — blueprint §7's named output
    type ("IOC list + narrative"), extended this session to carry the
    Linux security findings summary. Deliberately has no remediation/
    Incident Response field — both are explicitly out of scope for this
    framework."""

    model_config = ConfigDict(frozen=True)

    finding_count: int
    category_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    highest_composite_score: float = 0.0
    distinct_subject_count: int = 0
    top_findings: tuple[LinuxSecurityFindingSummaryInput, ...] = ()
    narrative: str = ""


class ThreatHunterAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    report: ThreatHuntingReport | None = None
    skipped_non_hunting_items: int = 0


def default_threat_hunter_agent_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `LinuxSecurityAssessmentTool`
    registered — mirrors `core.agents.vulnerability_agent.
    default_vulnerability_agent_tool_registry`'s shape exactly."""
    registry = ToolRegistry()
    registry.register(LinuxSecurityAssessmentTool())
    return registry


def _findings_from_state(records: list[object]) -> list[LinuxSecurityFindingSummaryInput]:
    """Filters `CaseInvestigationState.linux_security_records` down to
    well-formed plain-dict finding entries, skipping (never crashing on)
    anything else — the same "skip, don't crash" pattern
    `core.agents.vulnerability_agent._findings_from_state` uses."""
    findings: list[LinuxSecurityFindingSummaryInput] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        try:
            findings.append(LinuxSecurityFindingSummaryInput(**item))
        except (TypeError, ValueError):
            continue
    return findings


def _build_narrative(result: LinuxSecurityAssessmentOutput) -> str:
    """Deterministic, template-based narrative synthesis (constitution
    §1.9: no LLM call) — a short human-readable summary distinct from the
    raw counts, matching blueprint §7's "IOC list + narrative" output shape."""
    if result.finding_count == 0:
        return "No Linux security findings on this case's evidence to date."
    top_categories = sorted(result.category_counts.items(), key=lambda item: item[1], reverse=True)[
        :3
    ]
    category_summary = ", ".join(f"{name} ({count})" for name, count in top_categories)
    return (
        f"{result.finding_count} Linux security finding(s) across "
        f"{result.distinct_subject_count} subject(s); most common: {category_summary}; "
        f"highest composite score {result.highest_composite_score:.1f}/100."
    )


class ThreatHunterAgent(BaseAgent):
    """Aggregates the case's already-generated Linux security findings into
    a case-level `ThreatHuntingReport` (blueprint §7). Never performs its own
    detection, scoring, or finding generation — it consumes what
    `core.services.linux_security_service` already computed."""

    name: ClassVar[str] = "threat_hunter_agent"
    description: ClassVar[str] = (
        "Summarizes already-detected Linux security findings for a case into "
        "an aggregate threat-hunting report: counts by category/severity, "
        "highest composite score, and the highest-severity findings."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Confirm SSH-auth/syslog evidence is present before summarizing.",
        "Aggregate already-generated LinuxSecurityFinding data into a case-level report.",
        "Never recompute a detection, confidence, or risk score itself.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="cross_log_threat_hunting",
            description="Hunts for Linux security threats across SSH-auth/syslog evidence.",
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (LinuxSecurityAssessmentTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        hunting_items = 0
        skipped = 0
        for item in state.evidence:
            if not isinstance(item, NormalizedEvidence):
                continue
            if item.evidence_type in _THREAT_HUNTING_EVIDENCE_TYPES:
                hunting_items += 1
            else:
                skipped += 1

        if hunting_items == 0:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No SSH-auth/syslog evidence present on case state; insufficient "
                    "evidence to hunt (not the same as 'no threats found')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=ThreatHunterAgentResult(skipped_non_hunting_items=skipped).model_dump(
                    mode="json"
                ),
            )

        findings = _findings_from_state(state.linux_security_records)
        result = self.use_tool(
            LinuxSecurityAssessmentTool.name, LinuxSecurityAssessmentInput(findings=findings)
        )
        assert isinstance(result, LinuxSecurityAssessmentOutput)  # noqa: S101 - tool contract

        report = ThreatHuntingReport(
            finding_count=result.finding_count,
            category_counts=result.category_counts,
            severity_counts=result.severity_counts,
            highest_composite_score=result.highest_composite_score,
            distinct_subject_count=result.distinct_subject_count,
            top_findings=result.top_findings,
            narrative=_build_narrative(result),
        )
        state.findings = [*state.findings, report]

        thought = (
            f"Hunted {result.finding_count} Linux security finding(s) across "
            f"{result.distinct_subject_count} subject(s); highest composite score "
            f"{result.highest_composite_score:.1f}/100."
            if result.finding_count
            else "No Linux security findings detected; evidence coverage confirmed."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=ThreatHunterAgentResult(
                report=report, skipped_non_hunting_items=skipped
            ).model_dump(mode="json"),
        )
