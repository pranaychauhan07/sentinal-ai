"""Linux Security Advisor Service — orchestrates
`core.linux_advisor.advisory_engine.LinuxSecurityAdvisoryEngine` against one
`LINUX_COMMAND_INPUT` evidence artifact. Mirrors
`core/services/vulnerability_service.py`'s shape, minus the DB-persistence
stage — this framework never persists a `LinuxSecurityAdvice` (blueprint §7's
original "advisor" framing: a single request in, a single
`LinuxSecurityAdvice` out, no case-evidence lifecycle to track).

`core/services` importing `core/linux_advisor` and `core/parsers` directly
(rather than only `core/graph`) is a documented, deliberate exception —
`docs/dependency-rules.md` rule 4g / `docs/adr/0019-linux-security-advisor-
agent.md`: Linux command/permission advisory analysis is pre-investigation,
deterministic, and involves no agent/LLM reasoning, worded identically to
rule 4e/4f's precedent.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

from core.config import Settings
from core.linux_advisor.advisory_engine import LinuxSecurityAdvisoryEngine
from core.linux_advisor.audit import AuditAction, log_linux_advisor_audit_event
from core.linux_advisor.models import LinuxSecurityAdvice
from core.linux_advisor.risk_assessment import LinuxAdvisorRiskWeights, RiskAssessmentEngine
from core.logging import get_logger, logging_context
from core.parsers.models import NormalizedEvidence

_logger = get_logger(__name__)


class LinuxAdvisorAssessmentResult(BaseModel):
    """What `assess_linux_command_input()` returns — the one typed contract
    every caller (`core/services/case_service.py`, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    advice: LinuxSecurityAdvice


def build_linux_advisory_engine(settings: Settings) -> LinuxSecurityAdvisoryEngine:
    """Constructs a `LinuxSecurityAdvisoryEngine` wired from
    `Settings` — every configurable threshold/weight this framework uses
    lives in `core.config.settings.Settings`, never hardcoded here."""
    weights = LinuxAdvisorRiskWeights(
        highest_severity=settings.linux_advisor_risk_weight_highest_severity,
        highest_confidence=settings.linux_advisor_risk_weight_highest_confidence,
        finding_count=settings.linux_advisor_risk_weight_finding_count,
        critical_category=settings.linux_advisor_risk_weight_critical_category,
        corroboration=settings.linux_advisor_risk_weight_corroboration,
    )
    return LinuxSecurityAdvisoryEngine(
        max_lines=settings.linux_advisor_max_lines_per_artifact,
        max_total_chars=settings.linux_advisor_max_chars_per_artifact,
        risk_engine=RiskAssessmentEngine(weights=weights),
    )


def assess_linux_command_input(
    *,
    case_id: uuid.UUID,
    evidence: NormalizedEvidence,
    settings: Settings,
    engine: LinuxSecurityAdvisoryEngine | None = None,
) -> LinuxAdvisorAssessmentResult:
    """Runs the full Linux Security Advisory analysis for one
    `NormalizedEvidence` `LINUX_COMMAND_INPUT` artifact. No DB session is
    accepted — this framework never persists (module docstring); a
    malformed/oversized artifact raises
    `core.linux_advisor.exceptions.OversizedLinuxAdvisorInputError`, which
    the caller (`core/services/case_service.py`) is expected to let
    propagate as a rejected request, matching every other framework's
    oversized-input guard behavior.
    """
    engine = engine or build_linux_advisory_engine(settings)

    with logging_context(case_id=str(case_id)):
        lines = [record.raw_line for record in evidence.records if record.raw_line.strip()]
        advice = engine.analyze(lines)

        for command_risk in advice.analyzed_commands:
            if command_risk.matched_rule_ids:
                log_linux_advisor_audit_event(
                    action=AuditAction.ANALYZED_COMMAND,
                    subject=command_risk.command.command_name,
                    severity=command_risk.severity.value,
                    detail=command_risk.explanation,
                )
        for permission_risk in advice.permission_analyses:
            if permission_risk.matched_rule_ids:
                log_linux_advisor_audit_event(
                    action=AuditAction.ANALYZED_PERMISSION,
                    subject=permission_risk.permission.filename,
                    severity=permission_risk.severity.value,
                    detail=permission_risk.explanation,
                )
        if advice.skipped_line_count:
            log_linux_advisor_audit_event(
                action=AuditAction.LINE_SKIPPED,
                detail=f"{advice.skipped_line_count} line(s) skipped as malformed",
            )

        return LinuxAdvisorAssessmentResult(
            case_id=case_id, evidence_id=evidence.evidence_id, advice=advice
        )
