"""Unit tests for core/threat_intel/scoring.py — ThreatScoringEngine and
ConfidenceCalculator."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.threat_intel.models import IOCRecord, IOCType, SourceReliability, ThreatSeverity
from core.threat_intel.scoring import ConfidenceCalculator, ScoringWeights, ThreatScoringEngine


def _ioc(severity: ThreatSeverity = ThreatSeverity.MEDIUM, confidence: float = 0.8) -> IOCRecord:
    return IOCRecord(
        ioc_type=IOCType.IPV4,
        value="1.2.3.4",
        raw_value="1.2.3.4",
        source="test",
        severity=severity,
        confidence=confidence,
    )


@pytest.mark.unit
def test_scoring_weights_default_sums_to_one() -> None:
    ScoringWeights()  # must not raise


@pytest.mark.unit
def test_scoring_weights_rejects_non_unit_sum() -> None:
    with pytest.raises(ValidationError):
        ScoringWeights(
            confidence=0.9,
            severity=0.9,
            impact=0.0,
            likelihood=0.0,
            evidence_quality=0.0,
            source_reliability=0.0,
            rule_matches=0.0,
        )


@pytest.mark.unit
def test_higher_severity_yields_higher_composite_score() -> None:
    engine = ThreatScoringEngine()
    low = engine.score(
        _ioc(severity=ThreatSeverity.LOW),
        rule_matches=[],
        evidence_quality=0.8,
        source_reliability=SourceReliability.MEDIUM,
    )
    critical = engine.score(
        _ioc(severity=ThreatSeverity.CRITICAL),
        rule_matches=[],
        evidence_quality=0.8,
        source_reliability=SourceReliability.MEDIUM,
    )
    assert critical.composite_score > low.composite_score


@pytest.mark.unit
def test_composite_score_bounded_zero_to_hundred() -> None:
    engine = ThreatScoringEngine()
    score = engine.score(
        _ioc(severity=ThreatSeverity.CRITICAL, confidence=1.0),
        rule_matches=[],
        evidence_quality=1.0,
        source_reliability=SourceReliability.CONFIRMED,
    )
    assert 0.0 <= score.composite_score <= 100.0


@pytest.mark.unit
def test_custom_weights_change_scoring_outcome() -> None:
    severity_only = ScoringWeights(
        confidence=0.0,
        severity=1.0,
        impact=0.0,
        likelihood=0.0,
        evidence_quality=0.0,
        source_reliability=0.0,
        rule_matches=0.0,
    )
    engine = ThreatScoringEngine(weights=severity_only)
    score = engine.score(
        _ioc(severity=ThreatSeverity.HIGH, confidence=0.0),
        rule_matches=[],
        evidence_quality=0.0,
        source_reliability=SourceReliability.UNKNOWN,
    )
    assert score.composite_score == pytest.approx(75.0)


@pytest.mark.unit
def test_confidence_calculator_zero_when_validation_failed() -> None:
    calculator = ConfidenceCalculator()
    result = calculator.calculate(
        extraction_confidence=0.9,
        validation_passed=False,
        rule_match_count=5,
        source_reliability=SourceReliability.CONFIRMED,
    )
    assert result == 0.0


@pytest.mark.unit
def test_confidence_calculator_bounded_zero_to_one() -> None:
    calculator = ConfidenceCalculator()
    result = calculator.calculate(
        extraction_confidence=1.0,
        validation_passed=True,
        rule_match_count=10,
        source_reliability=SourceReliability.CONFIRMED,
    )
    assert 0.0 <= result <= 1.0


@pytest.mark.unit
def test_confidence_calculator_more_rule_matches_increase_confidence() -> None:
    calculator = ConfidenceCalculator()
    no_matches = calculator.calculate(
        extraction_confidence=0.5,
        validation_passed=True,
        rule_match_count=0,
        source_reliability=SourceReliability.UNKNOWN,
    )
    with_matches = calculator.calculate(
        extraction_confidence=0.5,
        validation_passed=True,
        rule_match_count=3,
        source_reliability=SourceReliability.UNKNOWN,
    )
    assert with_matches > no_matches
