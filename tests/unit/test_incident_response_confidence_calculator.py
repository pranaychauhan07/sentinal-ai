"""Unit tests for core/incident_response/confidence_calculator.py."""

from __future__ import annotations

import pytest

from core.incident_response.confidence_calculator import (
    calculate_plan_confidence,
    calculate_plan_risk_score,
)
from core.incident_response.models import (
    ResponseAction,
    ResponseCategory,
    ResponsePhase,
    ResponsePriority,
    ResponseRecommendation,
    ResponseTimeframe,
)

pytestmark = pytest.mark.unit


def _recommendation(confidence: float, risk_score: float) -> ResponseRecommendation:
    return ResponseRecommendation(
        action=ResponseAction(
            category=ResponseCategory.HOST_ISOLATION,
            phase=ResponsePhase.ISOLATION,
            title="t",
            description="d",
        ),
        timeframe=ResponseTimeframe.IMMEDIATE,
        priority=ResponsePriority.P1_IMMEDIATE,
        confidence=confidence,
        risk_score=risk_score,
        execution_order=1,
    )


def test_no_recommendations_yields_zero_confidence() -> None:
    assert calculate_plan_confidence((), skipped_record_count=0, considered_record_count=0) == 0.0


def test_confidence_is_mean_across_recommendations() -> None:
    recs = (_recommendation(1.0, 10.0), _recommendation(0.5, 10.0))
    result = calculate_plan_confidence(recs, skipped_record_count=0, considered_record_count=2)
    assert result == pytest.approx(0.75)


def test_confidence_discounted_by_skipped_record_fraction() -> None:
    recs = (_recommendation(1.0, 10.0),)
    clean = calculate_plan_confidence(recs, skipped_record_count=0, considered_record_count=1)
    discounted = calculate_plan_confidence(recs, skipped_record_count=1, considered_record_count=1)
    assert discounted < clean
    assert discounted == pytest.approx(0.5)


def test_no_recommendations_yields_zero_risk_score() -> None:
    assert calculate_plan_risk_score(()) == 0.0


def test_risk_score_is_the_maximum_across_recommendations() -> None:
    recs = (_recommendation(1.0, 30.0), _recommendation(1.0, 90.0), _recommendation(1.0, 10.0))
    assert calculate_plan_risk_score(recs) == 90.0
