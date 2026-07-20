"""Unit tests for core/owasp_security/risk_assessment.py."""

from __future__ import annotations

import pytest

from core.owasp_security.models import (
    OwaspCategory,
    SastFinding,
    SastSeverity,
    VulnerabilityCategory,
)
from core.owasp_security.risk_assessment import RiskAssessmentEngine, SastRiskWeights

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> SastFinding:
    defaults: dict[str, object] = {
        "category": VulnerabilityCategory.INSECURE_CONFIGURATION,
        "owasp_category": OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        "cwe_id": "CWE-16",
        "severity": SastSeverity.MEDIUM,
        "confidence": 0.7,
        "evidence_reference": "x",
        "explanation": "e",
        "recommended_remediation": "r",
        "source": "python_ast_analyzer",
    }
    defaults.update(overrides)
    return SastFinding(**defaults)  # type: ignore[arg-type]


def test_no_findings_is_info_with_full_confidence() -> None:
    engine = RiskAssessmentEngine()
    level, confidence, explanation, _dims = engine.assess(findings=[], distinct_sources=set())
    assert level == SastSeverity.INFO
    assert confidence == 1.0
    assert "No SAST findings" in explanation


def test_command_injection_yields_high_or_critical_risk() -> None:
    engine = RiskAssessmentEngine()
    findings = [
        _finding(severity=SastSeverity.CRITICAL, category=VulnerabilityCategory.COMMAND_INJECTION)
    ]
    level, _confidence, _explanation, _dims = engine.assess(
        findings=findings, distinct_sources={"python_ast_analyzer"}
    )
    assert level in (SastSeverity.HIGH, SastSeverity.CRITICAL)


def test_corroboration_across_multiple_sources() -> None:
    engine = RiskAssessmentEngine()
    findings = [_finding(), _finding(source="pattern_analyzer")]
    _l, _c, _e, dims_multi = engine.assess(
        findings=findings, distinct_sources={"python_ast_analyzer", "pattern_analyzer"}
    )
    _l2, _c2, _e2, dims_single = engine.assess(
        findings=findings, distinct_sources={"python_ast_analyzer"}
    )
    assert dims_multi.corroboration_score == 1.0
    assert dims_single.corroboration_score == 0.0


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="must sum to 1.0"):
        SastRiskWeights(
            highest_severity=0.9,
            highest_confidence=0.9,
            finding_count=0.9,
            critical_category=0.9,
            corroboration=0.9,
        )
