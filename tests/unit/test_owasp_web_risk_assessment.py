"""Unit tests for core/owasp_web/risk_assessment.py."""

from __future__ import annotations

import pytest

from core.owasp_web.models import OwaspCategory, OwaspFinding, WebSecuritySeverity
from core.owasp_web.risk_assessment import RiskAssessmentEngine, WebSecurityRiskWeights

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> OwaspFinding:
    defaults: dict[str, object] = {
        "category": OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        "severity": WebSecuritySeverity.MEDIUM,
        "confidence": 0.8,
        "evidence_reference": "x",
        "explanation": "e",
        "recommended_remediation": "r",
        "source": "header_analyzer",
    }
    defaults.update(overrides)
    return OwaspFinding(**defaults)  # type: ignore[arg-type]


def test_no_findings_is_info_with_full_confidence() -> None:
    engine = RiskAssessmentEngine()
    level, confidence, explanation, _dims = engine.assess(findings=[], distinct_sources=set())
    assert level == WebSecuritySeverity.INFO
    assert confidence == 1.0
    assert "No OWASP-mapped issues" in explanation


def test_single_critical_finding_yields_high_or_critical_risk() -> None:
    engine = RiskAssessmentEngine()
    findings = [
        _finding(
            severity=WebSecuritySeverity.CRITICAL, category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES
        )
    ]
    level, _confidence, _explanation, _dims = engine.assess(
        findings=findings, distinct_sources={"jwt_analyzer"}
    )
    assert level in (WebSecuritySeverity.HIGH, WebSecuritySeverity.CRITICAL)


def test_corroboration_across_multiple_sources_raises_score() -> None:
    engine = RiskAssessmentEngine()
    findings = [_finding(), _finding(source="cookie_analyzer")]
    _level, _confidence, _explanation, dims_multi = engine.assess(
        findings=findings, distinct_sources={"header_analyzer", "cookie_analyzer"}
    )
    _level2, _confidence2, _explanation2, dims_single = engine.assess(
        findings=findings, distinct_sources={"header_analyzer"}
    )
    assert dims_multi.corroboration_score == 1.0
    assert dims_single.corroboration_score == 0.0


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="must sum to 1.0"):
        WebSecurityRiskWeights(
            highest_severity=0.9,
            highest_confidence=0.9,
            finding_count=0.9,
            critical_category=0.9,
            corroboration=0.9,
        )
