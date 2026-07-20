"""OWASP Security (AST SAST) Service — orchestrates
`core.owasp_security.analysis_engine.SourceCodeAnalysisEngine` against one
`SOURCE_CODE` evidence artifact. Mirrors
`core/services/web_security_service.py`'s shape exactly, minus the
DB-persistence stage — this framework never persists a `SastAdvice`
(`docs/adr/0021`'s "advisor" framing: a single request in, a single
`SastAdvice` out, no case-evidence lifecycle to track).

`core/services` importing `core/owasp_security` and `core/parsers` directly
(rather than only `core/graph`) is a documented, deliberate exception —
`docs/dependency-rules.md` rule 4i: source-code SAST analysis is
pre-investigation, deterministic, and involves no agent/LLM reasoning,
worded identically to rule 4h's precedent.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

from core.config import Settings
from core.logging import get_logger, logging_context
from core.owasp_security.analysis_engine import SourceCodeAnalysisEngine
from core.owasp_security.audit import AuditAction, log_sast_audit_event
from core.owasp_security.exceptions import SastError
from core.owasp_security.models import SastAdvice
from core.owasp_security.risk_assessment import RiskAssessmentEngine, SastRiskWeights
from core.parsers.models import NormalizedEvidence

_logger = get_logger(__name__)


class SastAssessmentResult(BaseModel):
    """What `assess_source_code()` returns — the one typed contract every
    caller (`core/services/case_service.py`, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    advice: SastAdvice


def build_source_code_analysis_engine(settings: Settings) -> SourceCodeAnalysisEngine:
    """Constructs a `SourceCodeAnalysisEngine` wired from `Settings` — every
    configurable threshold/weight this framework uses lives in
    `core.config.settings.Settings`, never hardcoded here."""
    weights = SastRiskWeights(
        highest_severity=settings.owasp_security_risk_weight_highest_severity,
        highest_confidence=settings.owasp_security_risk_weight_highest_confidence,
        finding_count=settings.owasp_security_risk_weight_finding_count,
        critical_category=settings.owasp_security_risk_weight_critical_category,
        corroboration=settings.owasp_security_risk_weight_corroboration,
    )
    return SourceCodeAnalysisEngine(
        max_lines=settings.owasp_security_max_lines_per_artifact,
        max_total_chars=settings.owasp_security_max_chars_per_artifact,
        risk_engine=RiskAssessmentEngine(weights=weights),
    )


def assess_source_code(
    *,
    case_id: uuid.UUID,
    evidence: NormalizedEvidence,
    settings: Settings,
    engine: SourceCodeAnalysisEngine | None = None,
) -> SastAssessmentResult:
    """Runs the full SAST analysis for one `NormalizedEvidence` `SOURCE_CODE`
    artifact. No DB session is accepted — this framework never persists
    (module docstring); a malformed/oversized artifact raises
    `core.owasp_security.exceptions.OversizedSourceInputError`, which the
    caller (`core/services/case_service.py`) is expected to let propagate as
    a rejected request, matching every other framework's oversized-input
    guard behavior.
    """
    engine = engine or build_source_code_analysis_engine(settings)

    with logging_context(case_id=str(case_id)):
        filename = evidence.source
        source_text = evidence.records[0].raw_line if evidence.records else ""

        try:
            advice = engine.analyze(source_text, filename=filename)
        except SastError:
            raise

        for finding in advice.sast_findings:
            log_sast_audit_event(
                action=AuditAction.FINDING_DETECTED,
                subject=finding.category.value,
                severity=finding.severity.value,
                detail=finding.explanation,
            )
        if advice.parse_degraded:
            log_sast_audit_event(
                action=AuditAction.PARSE_DEGRADED,
                subject=str(filename),
                detail=advice.overall_explanation,
            )
        log_sast_audit_event(
            action=AuditAction.FILE_ANALYZED,
            subject=str(filename),
            severity=advice.overall_risk_level.value,
            detail=f"{len(advice.sast_findings)} finding(s), language={advice.language.value}",
        )

        return SastAssessmentResult(
            case_id=case_id, evidence_id=evidence.evidence_id, advice=advice
        )
