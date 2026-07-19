"""Phishing Investigation Agent — blueprint §7: "full email triage: sender/
domain analysis, URL risk scoring, content social-engineering detection,
attachment risk, aggregate risk score."

Milestone M2's second concrete specialist agent (`docs/roadmap.md`). Reads
`NormalizedEvidence` items of `evidence_type=EMAIL` already on
`CaseInvestigationState.evidence` (produced upstream by
`core/parsers/email_parser.py`), screens the subject/body through
`core.security.prompt_guard` *before* using that text for anything else
(constitution §4.11/§9/§10 — this is the first agent in the codebase
consuming attacker-controlled text), then calls
`core.tools.phishing_tools.PhishingScoringTool` to produce a
`PhishingVerdict` — never re-extracting IOCs or recomputing threat scores
itself (constitution §1.9).

Already-scored URL/domain/email IOCs for this evidence are read from
`CaseInvestigationState.extracted_indicators` — deliberately kept as plain
`dict[str, object]` entries (``{"evidence_id", "ioc_type", "composite_score"}``)
rather than typed `core.threat_intel.models.ScoredIOC` instances:
`docs/dependency-rules.md` rule 4 does not grant `core/agents` an import edge
onto `core/threat_intel` (only `core/services/threat_intel_service.py` and
`core/services/finding_service.py` get that documented exception, rules
4b/4c), and `core/graph/state.py` itself documents `extracted_indicators` as
staying generic until a future milestone's Threat Hunting Agent narrows it.
`core/services/case_service.py` reads the case's persisted `IOC` rows and
reduces each to this plain shape before hydrating state — agents never query
`core/db` directly either way.

Scoping note, matching `docs/adr/0014` point 4's precedent for
`SocAnalystAgent`: `PhishingVerdict` output is appended to
`CaseInvestigationState.findings` and this agent's `AgentExecutionResult.output`
— it is not written to the persisted `findings` DB table, which remains the
Finding & MITRE Engine's exclusive output. Reconciling the two is left to a
future milestone, not decided by default here.
"""

from __future__ import annotations

from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.parsers.models import EvidenceType, NormalizedEvidence, Severity
from core.security.prompt_guard import scan_text
from core.tools.phishing_tools import (
    PhishingScoringInput,
    PhishingScoringOutput,
    PhishingScoringTool,
)
from core.tools.registry import ToolRegistry

#: IOC type *string values* that speak to a phishing email's risk (embedded
#: URLs, linked domains, spoofed/lookalike sender addresses) — matched
#: against the plain `"ioc_type"` string on each `extracted_indicators`
#: entry (see module docstring for why this stays string-typed rather than
#: importing `core.threat_intel.models.IOCType`).
_RELEVANT_IOC_TYPES: frozenset[str] = frozenset({"url", "domain", "email"})


class PhishingVerdict(BaseModel):
    """One email's phishing-triage verdict — blueprint §7's `PhishingVerdict`
    (score 0-100, indicators, recommended actions)."""

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    source: str
    subject: str
    from_address: str
    risk_score: float
    risk_label: Severity
    indicators: tuple[str, ...] = ()
    prompt_injection_detected: bool = False
    recommended_action: str = ""


class PhishingAnalysisResult(BaseModel):
    """This agent's full output payload — what
    `AgentExecutionResult.output` is built from."""

    model_config = ConfigDict(frozen=True)

    verdicts: list[PhishingVerdict] = Field(default_factory=list)
    skipped_non_email_items: int = 0


def default_phishing_agent_tool_registry() -> ToolRegistry:
    """Constructs a `ToolRegistry` with `PhishingScoringTool` registered —
    mirrors `core.agents.soc_analyst_agent.default_soc_analyst_tool_registry`'s
    shape exactly, the one place `core/graph/investigation_graph.py`'s
    auto-registration helper needs to reach for."""
    registry = ToolRegistry()
    registry.register(PhishingScoringTool())
    return registry


def _recommended_action(risk_label: Severity) -> str:
    """Deterministic mapping from risk label to a recommended next action —
    a fixed table, never an LLM judgment call (constitution §1.9)."""
    return {
        Severity.CRITICAL: "Block sender/IOC(s) and isolate any recipient who interacted with it.",
        Severity.HIGH: "Escalate for analyst review; block linked URL(s)/domain(s).",
        Severity.MEDIUM: "Investigate further; monitor for recipient interaction.",
        Severity.LOW: "Monitor; no immediate action required.",
        Severity.INFO: "No action required; email appears benign.",
    }[risk_label]


def _attributed_ioc_scores(indicators: list[object], evidence_id: UUID) -> list[float]:
    """Filters `CaseInvestigationState.extracted_indicators` down to this
    evidence's already-scored URL/domain/email IOCs. Never recomputes a
    score — only reads the `"composite_score"` value
    `core.services.case_service` already hydrated from the persisted `IOC`
    row, which `core.threat_intel`'s Threat Scoring Engine already computed.
    Skips (never crashes on) any entry that isn't the expected plain-dict
    shape — the same "skip, don't crash" pattern
    `core.agents.soc_analyst_agent` uses for non-`NormalizedEvidence` items.
    """
    scores: list[float] = []
    for item in indicators:
        if not isinstance(item, dict):
            continue
        if item.get("evidence_id") != evidence_id:
            continue
        if item.get("ioc_type") not in _RELEVANT_IOC_TYPES:
            continue
        composite_score = item.get("composite_score")
        if isinstance(composite_score, int | float):
            scores.append(float(composite_score))
    return scores


class PhishingAgent(BaseAgent):
    """Sender/reply-to domain analysis, urgency/social-engineering keyword
    detection, attachment risk, and aggregate phishing risk scoring
    (blueprint §7). This agent never performs its own IOC extraction or
    threat scoring — it consumes what `core/threat_intel` already computed."""

    name: ClassVar[str] = "phishing_agent"
    description: ClassVar[str] = (
        "Triages email evidence for phishing indicators: sender/reply-to "
        "mismatch, urgency language, attachment risk, and attributed IOC "
        "threat scores, producing an aggregate risk verdict."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Screen email subject/body for prompt-injection patterns before use.",
        "Detect sender/reply-to domain mismatch and urgency/social-engineering language.",
        "Flag high-risk attachment extensions.",
        "Aggregate phishing risk from heuristics and already-scored attributed IOCs.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="email_triage", description="Triages email evidence for phishing indicators."
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (PhishingScoringTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        email_items: list[NormalizedEvidence] = []
        skipped = 0
        for item in state.evidence:
            if isinstance(item, NormalizedEvidence) and item.evidence_type == EvidenceType.EMAIL:
                email_items.append(item)
            elif isinstance(item, NormalizedEvidence):
                skipped += 1

        if not email_items:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No email evidence present on case state; insufficient "
                    "evidence to triage (not the same as 'no phishing found')."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=PhishingAnalysisResult(skipped_non_email_items=skipped).model_dump(
                    mode="json"
                ),
            )

        verdicts = [self._analyze_one(evidence, state) for evidence in email_items]
        state.findings = [*state.findings, *verdicts]

        highest_risk = max((v.risk_score for v in verdicts), default=0.0)
        flagged_count = sum(1 for v in verdicts if v.prompt_injection_detected)
        thought = (
            f"Triaged {len(verdicts)} email(s); highest risk score "
            f"{highest_risk:.1f}/100; {flagged_count} email(s) matched "
            f"prompt-injection patterns."
        )

        return AgentExecutionResult(
            agent_name=self.name,
            status=ExecutionStatus.SUCCEEDED,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=PhishingAnalysisResult(
                verdicts=verdicts, skipped_non_email_items=skipped
            ).model_dump(mode="json"),
        )

    def _analyze_one(
        self, evidence: NormalizedEvidence, state: CaseInvestigationState
    ) -> PhishingVerdict:
        subject = str(evidence.metadata.get("subject", ""))
        from_address = str(evidence.metadata.get("from_address", ""))
        reply_to_address = str(evidence.metadata.get("reply_to_address", ""))
        attachments_meta = evidence.metadata.get("attachments", [])
        attachments = attachments_meta if isinstance(attachments_meta, list) else []

        body_record = next((r for r in evidence.records if r.event_type == "email_body"), None)
        body_text = body_record.raw_line if body_record is not None else ""

        guard_result = scan_text(f"{subject}\n{body_text}")

        result = self.use_tool(
            PhishingScoringTool.name,
            PhishingScoringInput(
                from_address=from_address,
                reply_to_address=reply_to_address,
                subject=subject,
                body_text=body_text,
                attachments=attachments,
                attributed_ioc_scores=_attributed_ioc_scores(
                    state.extracted_indicators, evidence.evidence_id
                ),
                prompt_injection_flagged=guard_result.is_flagged,
            ),
        )
        assert isinstance(result, PhishingScoringOutput)  # noqa: S101 - tool contract, not user input
        scoring_output = result

        return PhishingVerdict(
            evidence_id=evidence.evidence_id,
            source=evidence.source,
            subject=subject,
            from_address=from_address,
            risk_score=scoring_output.risk_score,
            risk_label=scoring_output.risk_label,
            indicators=scoring_output.indicators,
            prompt_injection_detected=guard_result.is_flagged,
            recommended_action=_recommended_action(scoring_output.risk_label),
        )
