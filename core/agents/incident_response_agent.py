"""Incident Response Agent — blueprint §7's downstream, cross-agent
synthesizer: *"aggregated case findings (from any/all of the above agents)
... this agent is deliberately the 'downstream' consumer that ties a whole
case together ... pulls from every other agent's output already in case
state — never re-parses evidence itself."*

See `docs/adr/0023-incident-response-agent.md` for the full architecture
reasoning this agent's shape follows, in particular why it reads
pre-hydrated `*_records` fields and case-wide persisted `Finding` data
rather than sibling `agent_outputs` (Decision 1), and why the actual
response-playbook synthesis lives in `core/incident_response`, wrapped by
`core.tools.ir_tools.IncidentResponsePlanGenerationTool` (Decision 2) —
this agent never computes a severity, a risk score, a MITRE mapping, or a
response recommendation itself; it only normalizes already-computed signals
into `core.incident_response.inputs.IncidentInputFinding` and calls its one
declared tool.

Reads, in this fixed order:

1. `CaseInvestigationState.incident_response_finding_records` — this case's
   persisted `Finding` rows (SOC Analyst / Threat Hunting / Phishing-derived,
   case-wide across every prior upload), hydrated by
   `core/services/case_service.py::_hydrate_incident_response_records`.
2. `vulnerability_records`, `linux_security_records`, `linux_advisory_records`,
   `owasp_web_records`, `owasp_security_records` — the *current upload's*
   already-hydrated specialist input records (the same fields
   `VulnerabilityAssessmentAgent`/`ThreatHunterAgent`/`LinuxSecurityAgent`/
   `WebSecurityAgent`/`OwaspSecurityAgent` themselves read).

A malformed entry from any source is skipped, never fatal to the whole plan
(constitution §1.7) — `IncidentResponseAgentResult.skipped_record_count`
reports how many.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentResponsePlan, IncidentSeverity
from core.tools.ir_tools import (
    IncidentResponsePlanGenerationInput,
    IncidentResponsePlanGenerationOutput,
    IncidentResponsePlanGenerationTool,
)
from core.tools.registry import ToolRegistry


class IncidentResponseAgentResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    plan: IncidentResponsePlan | None = None
    skipped_record_count: int = 0


def default_incident_response_agent_tool_registry(
    *, max_findings_per_plan: int = 5_000
) -> ToolRegistry:
    """Constructs a `ToolRegistry` with `IncidentResponsePlanGenerationTool`
    registered — mirrors `core.agents.owasp_security_agent.
    default_owasp_security_agent_tool_registry`'s no-dependency shape (this
    tool needs no injected reference-data lookup, unlike
    `MitreMappingResolutionTool`)."""
    registry = ToolRegistry()
    registry.register(
        IncidentResponsePlanGenerationTool(max_findings_per_plan=max_findings_per_plan)
    )
    return registry


def _coerce_severity(value: object) -> IncidentSeverity:
    try:
        return IncidentSeverity(str(value))
    except ValueError:
        return IncidentSeverity.INFO


def _finding_from_persisted_record(record: dict[str, object]) -> IncidentInputFinding | None:
    """One entry from `incident_response_finding_records` — already-clean
    dicts built by `case_service._hydrate_incident_response_records` from
    persisted `Finding` rows (never re-parses `finding_data_json` here)."""
    try:
        title = str(record.get("title", ""))
        return IncidentInputFinding(
            finding_id=str(record.get("finding_id", "")),
            source="finding",
            title=title,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=float(record.get("risk_score", 0.0)),  # type: ignore[arg-type]
            confidence=float(record.get("confidence", 1.0)),  # type: ignore[arg-type]
            mitre_technique_ids=tuple(record.get("mitre_technique_ids") or ()),  # type: ignore[arg-type]
            mitre_tactic_ids=tuple(record.get("mitre_tactic_ids") or ()),  # type: ignore[arg-type]
            keywords=(title.lower(),),
        )
    except (TypeError, ValueError):
        return None


def _finding_from_vulnerability_record(record: dict[str, object]) -> IncidentInputFinding | None:
    try:
        title = str(record.get("title", ""))
        asset_ids = record.get("affected_asset_ids") or ()
        target = str(asset_ids[0]) if isinstance(asset_ids, list | tuple) and asset_ids else ""
        return IncidentInputFinding(
            finding_id=str(record.get("cve_id") or record.get("plugin_id") or ""),
            source="vulnerability_assessment",
            title=title,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=float(record.get("composite_score", 0.0)),  # type: ignore[arg-type]
            confidence=1.0,
            target=target,
            keywords=(title.lower(), "vulnerability"),
        )
    except (TypeError, ValueError):
        return None


def _finding_from_linux_security_record(record: dict[str, object]) -> IncidentInputFinding | None:
    try:
        title = str(record.get("title", ""))
        category = str(record.get("category", ""))
        subject = str(record.get("subject", ""))
        return IncidentInputFinding(
            finding_id=f"linux_security:{category}:{subject}",
            source="linux_security_threat_hunting",
            title=title,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=float(record.get("composite_score", 0.0)),  # type: ignore[arg-type]
            confidence=1.0,
            target=subject,
            keywords=(title.lower(), category.lower()),
        )
    except (TypeError, ValueError):
        return None


def _finding_from_linux_advisory_record(record: dict[str, object]) -> IncidentInputFinding | None:
    kind = record.get("kind")
    if kind not in ("command", "permission"):
        return None
    try:
        subject = str(record.get("command_name") or record.get("filename") or "")
        explanation = str(record.get("explanation", ""))
        return IncidentInputFinding(
            finding_id=f"linux_advisory:{kind}:{subject}",
            source="linux_advisory",
            title=explanation or subject,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=0.0,
            confidence=float(record.get("confidence", 1.0)),  # type: ignore[arg-type]
            target=subject,
            keywords=(explanation.lower(), kind),
        )
    except (TypeError, ValueError):
        return None


def _finding_from_owasp_web_record(record: dict[str, object]) -> IncidentInputFinding | None:
    if record.get("kind") != "finding":
        return None
    try:
        category = str(record.get("category", ""))
        explanation = str(record.get("explanation", ""))
        evidence_reference = str(record.get("evidence_reference", ""))
        return IncidentInputFinding(
            finding_id=f"owasp_web:{category}:{evidence_reference}",
            source="owasp_web_security",
            title=explanation or category,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=0.0,
            confidence=float(record.get("confidence", 1.0)),  # type: ignore[arg-type]
            keywords=(category.lower(),),
        )
    except (TypeError, ValueError):
        return None


def _finding_from_owasp_security_record(record: dict[str, object]) -> IncidentInputFinding | None:
    if record.get("kind") != "finding":
        return None
    try:
        category = str(record.get("category", ""))
        explanation = str(record.get("explanation", ""))
        evidence_reference = str(record.get("evidence_reference", ""))
        return IncidentInputFinding(
            finding_id=f"owasp_security:{category}:{evidence_reference}",
            source="owasp_source_code_review",
            title=explanation or category,
            severity=_coerce_severity(record.get("severity", "info")),
            risk_score=0.0,
            confidence=float(record.get("confidence", 1.0)),  # type: ignore[arg-type]
            keywords=(category.lower(),),
        )
    except (TypeError, ValueError):
        return None


_ConverterFn = Callable[[dict[str, object]], IncidentInputFinding | None]

#: One converter per state field this agent reads, applied uniformly by
#: `_collect_findings` — adding a future subsystem's records only means
#: adding one more `(field_name, converter)` pair here.
_RECORD_CONVERTERS: tuple[tuple[str, _ConverterFn], ...] = (
    ("incident_response_finding_records", _finding_from_persisted_record),
    ("vulnerability_records", _finding_from_vulnerability_record),
    ("linux_security_records", _finding_from_linux_security_record),
    ("linux_advisory_records", _finding_from_linux_advisory_record),
    ("owasp_web_records", _finding_from_owasp_web_record),
    ("owasp_security_records", _finding_from_owasp_security_record),
)


def _collect_findings(state: CaseInvestigationState) -> tuple[list[IncidentInputFinding], int]:
    findings: list[IncidentInputFinding] = []
    skipped = 0
    for field_name, converter in _RECORD_CONVERTERS:
        records = getattr(state, field_name, None) or []
        for item in records:
            if not isinstance(item, dict):
                skipped += 1
                continue
            result = converter(item)
            if result is None:
                skipped += 1
            else:
                findings.append(result)
    return findings, skipped


class IncidentResponseAgent(BaseAgent):
    """Synthesizes a case's already-computed cross-subsystem findings into a
    deterministic NIST SP 800-61-aligned `IncidentResponsePlan`. Never
    parses evidence, never computes a severity/risk/MITRE mapping/response
    recommendation itself — see module docstring."""

    name: ClassVar[str] = "incident_response_agent"
    description: ClassVar[str] = (
        "Synthesizes a case's already-computed findings across every specialist agent "
        "into a deterministic, NIST SP 800-61-aligned incident response plan."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Normalize already-computed findings from every upstream subsystem into one shape.",
        "Never recompute a severity, risk score, or MITRE mapping itself.",
        "Return a DEGRADED, zero-recommendation result rather than a forced guess when no "
        "findings are available yet.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="incident_response_synthesis",
            description=(
                "Synthesizes case-wide findings into a deterministic incident response plan."
            ),
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (IncidentResponsePlanGenerationTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        findings, skipped = _collect_findings(state)

        if not findings:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No findings available for this case yet; insufficient evidence to "
                    "generate a response plan (not the same as 'no incident')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=IncidentResponseAgentResult(skipped_record_count=skipped).model_dump(
                    mode="json"
                ),
            )

        result = self.use_tool(
            IncidentResponsePlanGenerationTool.name,
            IncidentResponsePlanGenerationInput(
                case_id=str(state.case_id),
                findings=findings,
                skipped_record_count=skipped,
            ),
        )
        assert isinstance(result, IncidentResponsePlanGenerationOutput)  # noqa: S101 - tool contract

        plan = result.plan
        state.findings = [*state.findings, plan]

        thought = (
            f"Synthesized {len(plan.recommendations)} response recommendation(s) across "
            f"{len(findings)} finding(s); incident severity '{plan.incident_severity.value}', "
            f"overall risk {plan.overall_risk_score:.1f}."
        )
        if plan.plan_degraded:
            thought += f" Plan is degraded: {plan.degraded_reason}"

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.DEGRADED if plan.plan_degraded else ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore(value=plan.overall_confidence),
            output=IncidentResponseAgentResult(plan=plan, skipped_record_count=skipped).model_dump(
                mode="json"
            ),
        )
