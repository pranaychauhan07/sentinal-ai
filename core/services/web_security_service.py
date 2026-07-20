"""Web Security Advisory Service — orchestrates
`core.owasp_web.advisory_engine.WebSecurityAdvisoryEngine` against one
`HTTP_TRANSACTION` evidence artifact. Mirrors
`core/services/linux_advisor_service.py`'s shape exactly, minus the
DB-persistence stage — this framework never persists a `WebSecurityAdvice`
(`docs/adr/0020-owasp-web-security-agent.md`'s "advisor" framing: a single
request in, a single `WebSecurityAdvice` out, no case-evidence lifecycle to
track).

`core/services` importing `core/owasp_web` and `core/parsers` directly
(rather than only `core/graph`) is a documented, deliberate exception —
`docs/dependency-rules.md` rule 4h / `docs/adr/0020-owasp-web-security-agent.md`:
HTTP security analysis is pre-investigation, deterministic, and involves no
agent/LLM reasoning, worded identically to rule 4e/4f/4g's precedent.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

from core.config import Settings
from core.logging import get_logger, logging_context
from core.owasp_web.advisory_engine import WebSecurityAdvisoryEngine
from core.owasp_web.audit import AuditAction, log_web_security_audit_event
from core.owasp_web.models import WebSecurityAdvice
from core.owasp_web.risk_assessment import RiskAssessmentEngine, WebSecurityRiskWeights
from core.parsers.models import NormalizedEvidence

_logger = get_logger(__name__)


class WebSecurityAssessmentResult(BaseModel):
    """What `assess_http_transaction()` returns — the one typed contract
    every caller (`core/services/case_service.py`, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    advice: WebSecurityAdvice


def build_web_security_advisory_engine(settings: Settings) -> WebSecurityAdvisoryEngine:
    """Constructs a `WebSecurityAdvisoryEngine` wired from `Settings` — every
    configurable threshold/weight this framework uses lives in
    `core.config.settings.Settings`, never hardcoded here."""
    weights = WebSecurityRiskWeights(
        highest_severity=settings.owasp_web_risk_weight_highest_severity,
        highest_confidence=settings.owasp_web_risk_weight_highest_confidence,
        finding_count=settings.owasp_web_risk_weight_finding_count,
        critical_category=settings.owasp_web_risk_weight_critical_category,
        corroboration=settings.owasp_web_risk_weight_corroboration,
    )
    return WebSecurityAdvisoryEngine(
        max_lines=settings.owasp_web_max_lines_per_artifact,
        max_total_chars=settings.owasp_web_max_chars_per_artifact,
        risk_engine=RiskAssessmentEngine(weights=weights),
    )


def assess_http_transaction(
    *,
    case_id: uuid.UUID,
    evidence: NormalizedEvidence,
    settings: Settings,
    engine: WebSecurityAdvisoryEngine | None = None,
) -> WebSecurityAssessmentResult:
    """Runs the full Web Security Advisory analysis for one
    `NormalizedEvidence` `HTTP_TRANSACTION` artifact. No DB session is
    accepted — this framework never persists (module docstring); a
    malformed/oversized artifact raises
    `core.owasp_web.exceptions.OversizedWebSecurityInputError`, which the
    caller (`core/services/case_service.py`) is expected to let propagate as
    a rejected request, matching every other framework's oversized-input
    guard behavior.
    """
    engine = engine or build_web_security_advisory_engine(settings)

    with logging_context(case_id=str(case_id)):
        lines = [record.raw_line for record in evidence.records if record.raw_line.strip()]
        advice = engine.analyze(lines)

        for finding in advice.header_findings:
            log_web_security_audit_event(
                action=AuditAction.ANALYZED_HEADER,
                subject=finding.header_name,
                severity=finding.severity.value,
                detail=finding.explanation,
            )
        for cookie_finding in advice.cookie_findings:
            log_web_security_audit_event(
                action=AuditAction.ANALYZED_COOKIE,
                subject=cookie_finding.cookie.name,
                severity=cookie_finding.severity.value,
                detail=cookie_finding.explanation,
            )
        for jwt_finding in advice.jwt_findings:
            log_web_security_audit_event(
                action=AuditAction.ANALYZED_JWT,
                subject=jwt_finding.jwt.alg,
                severity=jwt_finding.severity.value,
                detail=jwt_finding.explanation,
            )
        for misconfig_finding in advice.misconfiguration_findings:
            log_web_security_audit_event(
                action=AuditAction.ANALYZED_MISCONFIGURATION,
                subject=misconfig_finding.raw_text,
                severity=misconfig_finding.severity.value,
                detail=misconfig_finding.explanation,
            )
        if advice.skipped_line_count:
            log_web_security_audit_event(
                action=AuditAction.LINE_SKIPPED,
                detail=f"{advice.skipped_line_count} line(s) skipped as malformed",
            )

        return WebSecurityAssessmentResult(
            case_id=case_id, evidence_id=evidence.evidence_id, advice=advice
        )
