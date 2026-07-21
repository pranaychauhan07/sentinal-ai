"""Report Generator Agent — blueprint §7's *"Assembles all case findings into
module-specific and case-level executive ... reports... deterministic — the
... report is templated, not LLM-freeform, so reports are reproducible."*

See `docs/adr/0024-report-generator-agent.md` for the full architecture
reasoning this agent's shape follows: it is wired exactly like
`MitreMappingAgent`/`IncidentResponseAgent` (a tenth specialist node,
cross-cutting, regenerating a comprehensive Technical Investigation Report
on every evidence upload), and reads only pre-hydrated `*_records` state
fields — never sibling `agent_outputs` from the same run (the same
superstep-isolation reasoning ADR-0023 already established).

Reads, in this fixed order:

1. `CaseInvestigationState.incident_response_finding_records` — this case's
   persisted `Finding` rows, case-wide (the same field `IncidentResponseAgent`
   reads).
2. `mitre_mapping_records` — this case's resolved MITRE technique mappings,
   case-wide.
3. `extracted_indicators` — this upload's already-scored IOCs.
4. `evidence` — this upload's normalized evidence (for a count/type summary
   only, never the raw content).
5. `thoughts` — this run's ReAct trail (the Investigation Timeline section;
   necessarily scoped to this run, not the case's full cross-upload
   history — see ADR-0024, Decision 2).
6. `vulnerability_records`, `linux_security_records`, `linux_advisory_records`,
   `owasp_web_records`, `owasp_security_records` — the current upload's
   already-hydrated specialist input records.
7. `incident_response_plan_record` — this case's most recently *persisted*
   `IncidentResponsePlan` (one run behind this run's own plan — ADR-0024,
   Decision 2), or `None` if none has ever been persisted.

A malformed entry from any source is skipped, never fatal to the whole
report (constitution §1.7) — `ReportGeneratorAgentResult.skipped_record_count`
reports how many.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import NormalizedEvidence
from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import GeneratedReport, ReportType
from core.tools.registry import ToolRegistry
from core.tools.report_tools import (
    ReportGenerationInput,
    ReportGenerationOutput,
    ReportGenerationTool,
)


class ReportGeneratorAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    report: GeneratedReport | None = None
    skipped_record_count: int = 0


def default_report_generator_agent_tool_registry(
    *, max_records_per_report: int = 20_000
) -> ToolRegistry:
    """Constructs a `ToolRegistry` with `ReportGenerationTool` registered —
    mirrors `core.agents.incident_response_agent.
    default_incident_response_agent_tool_registry`'s no-dependency shape
    (this tool needs no injected reference-data lookup)."""
    registry = ToolRegistry()
    registry.register(ReportGenerationTool(max_records_per_report=max_records_per_report))
    return registry


def _dict_records(records: list[object]) -> tuple[list[dict[str, object]], int]:
    """Filters `records` down to well-formed dicts, counting skipped
    (non-dict) entries — the same "skip malformed, never crash" shape
    `IncidentResponseAgent._collect_findings` already established."""
    clean: list[dict[str, object]] = []
    skipped = 0
    for item in records:
        if isinstance(item, dict):
            clean.append(item)
        else:
            skipped += 1
    return clean, skipped


def _build_evidence_item(evidence: object) -> dict[str, object] | None:
    if isinstance(evidence, NormalizedEvidence):
        return {
            "evidence_type": evidence.evidence_type.value,
            "record_count": evidence.record_count,
        }
    return None


def _build_context(state: CaseInvestigationState) -> tuple[ReportGenerationContext, int]:
    skipped_total = 0

    findings, skipped = _dict_records(list(state.incident_response_finding_records))
    skipped_total += skipped
    mitre_mappings, skipped = _dict_records(list(state.mitre_mapping_records))
    skipped_total += skipped
    iocs, skipped = _dict_records(list(state.extracted_indicators))
    skipped_total += skipped
    vulnerability_records, skipped = _dict_records(list(state.vulnerability_records))
    skipped_total += skipped
    linux_security_records, skipped = _dict_records(list(state.linux_security_records))
    skipped_total += skipped
    linux_advisory_records, skipped = _dict_records(list(state.linux_advisory_records))
    skipped_total += skipped
    owasp_web_records, skipped = _dict_records(list(state.owasp_web_records))
    skipped_total += skipped
    owasp_security_records, skipped = _dict_records(list(state.owasp_security_records))
    skipped_total += skipped

    evidence_items: list[dict[str, object]] = []
    for evidence in state.evidence:
        item = _build_evidence_item(evidence)
        if item is None:
            skipped_total += 1
        else:
            evidence_items.append(item)

    thought_entries = [
        {
            "agent_name": thought.agent_name,
            "thought": thought.thought,
            "confidence": thought.confidence,
            "created_at": thought.created_at.isoformat(),
        }
        for thought in state.thoughts
    ]

    incident_response_plan = (
        state.incident_response_plan_record
        if isinstance(state.incident_response_plan_record, dict)
        else None
    )

    context = ReportGenerationContext(
        case_id=str(state.case_id),
        findings=tuple(findings),
        mitre_mappings=tuple(mitre_mappings),
        iocs=tuple(iocs),
        evidence_items=tuple(evidence_items),
        thought_entries=tuple(thought_entries),
        vulnerability_records=tuple(vulnerability_records),
        linux_security_records=tuple(linux_security_records),
        linux_advisory_records=tuple(linux_advisory_records),
        owasp_web_records=tuple(owasp_web_records),
        owasp_security_records=tuple(owasp_security_records),
        incident_response_plan=incident_response_plan,
        skipped_record_count=skipped_total,
    )
    return context, skipped_total


class ReportGeneratorAgent(BaseAgent):
    """Assembles a case's already-computed cross-subsystem output into a
    deterministic, strongly-typed `GeneratedReport`. Never parses evidence,
    never computes a severity/risk/MITRE mapping/confidence itself — see
    module docstring."""

    name: ClassVar[str] = "report_generator_agent"
    description: ClassVar[str] = (
        "Assembles a case's already-computed findings, IOCs, MITRE mappings, and "
        "incident response plan into a deterministic, strongly-typed investigation report."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Normalize already-computed data from every upstream subsystem into one shape.",
        "Never recompute a severity, risk score, MITRE mapping, or confidence itself.",
        "Return a DEGRADED result with an explicit reason rather than a fabricated report "
        "when no data is available yet.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="report_generation",
            description="Generates a deterministic, strongly-typed investigation report.",
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (ReportGenerationTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        context, skipped = _build_context(state)

        if not context.findings and not context.mitre_mappings and not context.iocs:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No findings, MITRE mappings, or IOCs available for this case yet; "
                    "insufficient evidence to generate a report."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=ReportGeneratorAgentResult(skipped_record_count=skipped).model_dump(
                    mode="json"
                ),
            )

        result = self.use_tool(
            ReportGenerationTool.name,
            ReportGenerationInput(context=context, report_type=ReportType.TECHNICAL_INVESTIGATION),
        )
        assert isinstance(result, ReportGenerationOutput)  # noqa: S101 - tool contract

        report = result.report
        thought = (
            f"Generated a '{report.report_type.value}' report with {len(report.sections)} "
            f"section(s); confidence {report.confidence:.2f}."
        )
        if report.degraded:
            thought += f" Report is degraded: {'; '.join(report.degraded_reasons)}"

        agent_result = ReportGeneratorAgentResult(report=report, skipped_record_count=skipped)
        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.DEGRADED if report.degraded else ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore(value=report.confidence),
            output=agent_result.model_dump(mode="json"),
        )
