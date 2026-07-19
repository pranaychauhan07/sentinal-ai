"""Unit tests for core/threat_intel/classification.py —
ThreatClassificationEngine."""

from __future__ import annotations

import pytest

from core.threat_intel.classification import ThreatClassificationEngine
from core.threat_intel.models import RuleMatchResult, ThreatCategory, ThreatScore


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
