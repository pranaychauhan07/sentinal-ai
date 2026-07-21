"""Unit tests for core/threat_intel/classification.py —
ThreatClassificationEngine."""

from __future__ import annotations

import pytest

from core.threat_intel.classification import (
    ThreatClassificationEngine,
    derive_severity_from_classification,
)
from core.threat_intel.models import (
    IOCClassification,
    RuleMatchResult,
    ThreatCategory,
    ThreatScore,
    ThreatSeverity,
)


def _score(composite_score: float, confidence: float = 0.5) -> ThreatScore:
    return ThreatScore(
        confidence=confidence,
        severity_weight=0.5,
        impact=0.5,
        likelihood=0.5,
        evidence_quality=0.5,
        source_reliability=0.5,
        rule_match_score=0.0,
        composite_score=composite_score,
    )


@pytest.mark.unit
def test_score_above_malicious_threshold_classifies_malicious() -> None:
    engine = ThreatClassificationEngine(malicious_threshold=70.0, suspicious_threshold=40.0)
    result = engine.classify(_score(85.0), [])
    assert result.category == ThreatCategory.MALICIOUS


@pytest.mark.unit
def test_score_between_thresholds_classifies_suspicious() -> None:
    engine = ThreatClassificationEngine(malicious_threshold=70.0, suspicious_threshold=40.0)
    result = engine.classify(_score(55.0), [])
    assert result.category == ThreatCategory.SUSPICIOUS


@pytest.mark.unit
def test_score_below_suspicious_threshold_classifies_benign() -> None:
    engine = ThreatClassificationEngine(malicious_threshold=70.0, suspicious_threshold=40.0)
    result = engine.classify(_score(10.0, confidence=0.5), [])
    assert result.category == ThreatCategory.BENIGN


@pytest.mark.unit
def test_zero_confidence_low_score_classifies_unknown() -> None:
    engine = ThreatClassificationEngine(malicious_threshold=70.0, suspicious_threshold=40.0)
    result = engine.classify(_score(0.0, confidence=0.0), [])
    assert result.category == ThreatCategory.UNKNOWN


@pytest.mark.unit
def test_a_rule_match_elevates_low_score_to_suspicious() -> None:
    engine = ThreatClassificationEngine(malicious_threshold=70.0, suspicious_threshold=40.0)
    match = RuleMatchResult(rule_id="r1", rule_name="test", matched=True)
    result = engine.classify(_score(5.0, confidence=0.5), [match])
    assert result.category == ThreatCategory.SUSPICIOUS
    assert result.matched_rule_ids == ("r1",)


@pytest.mark.unit
def test_invalid_threshold_ordering_raises() -> None:
    with pytest.raises(ValueError, match="Thresholds"):
        ThreatClassificationEngine(malicious_threshold=10.0, suspicious_threshold=50.0)


# --- derive_severity_from_classification -----------------------------------
# Regression coverage for a real bug: `IOCRecord.severity` previously stayed
# at its Pydantic default (INFO) for every IOC forever, because nothing in
# the pipeline ever derived a real value from the classification this
# engine already computes — silently disconnecting Finding-level severity
# (which reads `ioc.record.severity` as its base) from the actual threat
# signal. These tests pin the derivation directly.


def _classification(category: ThreatCategory) -> IOCClassification:
    return IOCClassification(category=category, reason="test fixture")


@pytest.mark.unit
def test_malicious_high_score_derives_critical() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.MALICIOUS), _score(95.0)
    )
    assert severity == ThreatSeverity.CRITICAL


@pytest.mark.unit
def test_malicious_lower_score_derives_high_not_critical() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.MALICIOUS), _score(75.0)
    )
    assert severity == ThreatSeverity.HIGH


@pytest.mark.unit
def test_suspicious_high_score_derives_medium() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.SUSPICIOUS), _score(60.0)
    )
    assert severity == ThreatSeverity.MEDIUM


@pytest.mark.unit
def test_suspicious_lower_score_derives_low() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.SUSPICIOUS), _score(45.0)
    )
    assert severity == ThreatSeverity.LOW


@pytest.mark.unit
def test_benign_derives_info() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.BENIGN), _score(10.0)
    )
    assert severity == ThreatSeverity.INFO


@pytest.mark.unit
def test_unknown_derives_info() -> None:
    severity = derive_severity_from_classification(
        _classification(ThreatCategory.UNKNOWN), _score(0.0)
    )
    assert severity == ThreatSeverity.INFO


@pytest.mark.unit
def test_derivation_is_deterministic() -> None:
    classification = _classification(ThreatCategory.MALICIOUS)
    score = _score(80.0)
    first = derive_severity_from_classification(classification, score)
    second = derive_severity_from_classification(classification, score)
    assert first == second == ThreatSeverity.HIGH
