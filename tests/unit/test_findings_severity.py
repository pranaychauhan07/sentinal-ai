"""Unit tests for core/findings/severity.py."""

from __future__ import annotations

import pytest
from tests.unit._finding_test_helpers import make_scored_ioc

from core.findings.models import (
    FindingConfidence,
    FindingPriority,
    FindingSeverity,
    MappingConfidenceFactors,
    MitreMapping,
)
from core.findings.severity import assign_priority, assign_severity, calculate_risk_score
from core.threat_intel.models import ThreatSeverity


def _confidence(composite: float) -> FindingConfidence:
    return FindingConfidence(
        ioc_quality=composite,
        evidence_quality=composite,
        supporting_indicator_score=composite,
        rule_strength=composite,
        mapping_quality=composite,
        source_reliability=composite,
        historical_evidence=composite,
        composite=composite,
    )


def _mapping(tactic_ids: tuple[str, ...] = ()) -> MitreMapping:
    return MitreMapping(
        technique_id="T1486",
        tactic_ids=tactic_ids,
        confidence=0.7,
        mapping_source="rule_based",
        attack_spec_version="1.0-test",
        factors=MappingConfidenceFactors(
            rule_strength=0.6,
            ioc_confidence=0.7,
            evidence_quality=0.7,
            supporting_indicator_count=1,
        ),
    )


@pytest.mark.unit
def test_assign_severity_requires_at_least_one_ioc() -> None:
    with pytest.raises(ValueError, match="at least one"):
        assign_severity([], [], _confidence(0.5))


@pytest.mark.unit
def test_assign_severity_uses_max_ioc_severity() -> None:
    iocs = [
        make_scored_ioc(severity=ThreatSeverity.LOW, value="1"),
        make_scored_ioc(severity=ThreatSeverity.HIGH, value="2"),
    ]
    severity = assign_severity(iocs, [], _confidence(0.5))
    assert severity is FindingSeverity.HIGH


@pytest.mark.unit
def test_high_impact_tactic_escalates_severity_when_confident() -> None:
    iocs = [make_scored_ioc(severity=ThreatSeverity.MEDIUM)]
    escalated = assign_severity(iocs, [_mapping(("TA0040",))], _confidence(0.8))
    assert escalated is FindingSeverity.HIGH


@pytest.mark.unit
def test_high_impact_tactic_does_not_escalate_when_low_confidence() -> None:
    iocs = [make_scored_ioc(severity=ThreatSeverity.MEDIUM)]
    not_escalated = assign_severity(iocs, [_mapping(("TA0040",))], _confidence(0.2))
    assert not_escalated is FindingSeverity.MEDIUM


@pytest.mark.unit
def test_severity_never_escalates_past_critical() -> None:
    iocs = [make_scored_ioc(severity=ThreatSeverity.CRITICAL)]
    severity = assign_severity(iocs, [_mapping(("TA0040",))], _confidence(0.9))
    assert severity is FindingSeverity.CRITICAL


@pytest.mark.unit
def test_assign_priority_critical_severity_is_always_p1() -> None:
    assert (
        assign_priority(FindingSeverity.CRITICAL, _confidence(0.1)) is FindingPriority.P1_CRITICAL
    )


@pytest.mark.unit
def test_assign_priority_high_severity_depends_on_confidence() -> None:
    assert assign_priority(FindingSeverity.HIGH, _confidence(0.7)) is FindingPriority.P1_CRITICAL
    assert assign_priority(FindingSeverity.HIGH, _confidence(0.2)) is FindingPriority.P2_HIGH


@pytest.mark.unit
def test_assign_priority_info_severity_is_always_p4() -> None:
    assert assign_priority(FindingSeverity.INFO, _confidence(0.99)) is FindingPriority.P4_LOW


@pytest.mark.unit
def test_calculate_risk_score_bounded() -> None:
    score = calculate_risk_score(FindingSeverity.CRITICAL, _confidence(1.0))
    assert 0.0 <= score <= 100.0
    assert score == pytest.approx(100.0)


@pytest.mark.unit
def test_calculate_risk_score_zero_for_info_and_zero_confidence() -> None:
    score = calculate_risk_score(FindingSeverity.INFO, _confidence(0.0))
    assert score == 0.0


@pytest.mark.unit
def test_calculate_risk_score_increases_with_severity() -> None:
    low = calculate_risk_score(FindingSeverity.LOW, _confidence(0.5))
    high = calculate_risk_score(FindingSeverity.HIGH, _confidence(0.5))
    assert high > low
