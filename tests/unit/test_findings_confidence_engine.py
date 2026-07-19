"""Unit tests for core/findings/confidence_engine.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from tests.unit._finding_test_helpers import make_scored_ioc

from core.findings.confidence_engine import ConfidenceEngine, FindingConfidenceWeights
from core.findings.models import MappingConfidenceFactors, MitreMapping
from core.threat_intel.models import SourceReliability


def _mapping(confidence: float = 0.7, rule_strength: float = 0.6) -> MitreMapping:
    return MitreMapping(
        technique_id="T1110",
        confidence=confidence,
        mapping_source="rule_based",
        attack_spec_version="1.0-test",
        factors=MappingConfidenceFactors(
            rule_strength=rule_strength,
            ioc_confidence=0.8,
            evidence_quality=0.7,
            supporting_indicator_count=1,
        ),
    )


@pytest.mark.unit
def test_weights_default_sums_to_one() -> None:
    FindingConfidenceWeights()  # must not raise


@pytest.mark.unit
def test_weights_rejects_non_unit_sum() -> None:
    with pytest.raises(ValidationError):
        FindingConfidenceWeights(
            ioc_quality=0.9,
            evidence_quality=0.9,
            supporting_indicator_score=0.0,
            rule_strength=0.0,
            mapping_quality=0.0,
            source_reliability=0.0,
            historical_evidence=0.0,
        )


@pytest.mark.unit
def test_calculate_requires_at_least_one_ioc() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ConfidenceEngine().calculate([], [])


@pytest.mark.unit
def test_calculate_returns_bounded_composite() -> None:
    engine = ConfidenceEngine()
    confidence = engine.calculate(
        [make_scored_ioc(confidence=1.0, evidence_quality=1.0)],
        [_mapping()],
        source_reliability=SourceReliability.CONFIRMED,
    )
    assert 0.0 <= confidence.composite <= 1.0


@pytest.mark.unit
def test_no_mappings_zeroes_mapping_and_rule_dimensions() -> None:
    engine = ConfidenceEngine()
    confidence = engine.calculate([make_scored_ioc()], [])
    assert confidence.mapping_quality == 0.0
    assert confidence.rule_strength == 0.0


@pytest.mark.unit
def test_more_supporting_indicators_increase_supporting_indicator_score() -> None:
    engine = ConfidenceEngine()
    one = engine.calculate([make_scored_ioc()], [_mapping()])
    many = engine.calculate([make_scored_ioc(value=str(i)) for i in range(5)], [_mapping()])
    assert many.supporting_indicator_score > one.supporting_indicator_score


@pytest.mark.unit
def test_higher_source_reliability_increases_composite() -> None:
    engine = ConfidenceEngine()
    unknown = engine.calculate(
        [make_scored_ioc()], [_mapping()], source_reliability=SourceReliability.UNKNOWN
    )
    confirmed = engine.calculate(
        [make_scored_ioc()], [_mapping()], source_reliability=SourceReliability.CONFIRMED
    )
    assert confirmed.composite > unknown.composite


@pytest.mark.unit
def test_custom_weights_isolate_one_dimension() -> None:
    weights = FindingConfidenceWeights(
        ioc_quality=0.0,
        evidence_quality=0.0,
        supporting_indicator_score=0.0,
        rule_strength=1.0,
        mapping_quality=0.0,
        source_reliability=0.0,
        historical_evidence=0.0,
    )
    engine = ConfidenceEngine(weights=weights)
    confidence = engine.calculate([make_scored_ioc()], [_mapping(rule_strength=0.6)])
    assert confidence.composite == pytest.approx(0.6)
