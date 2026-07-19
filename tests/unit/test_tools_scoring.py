"""Unit tests for core/tools/scoring.py."""

from __future__ import annotations

import pytest

from core.parsers.models import Severity
from core.tools.scoring import (
    RiskScoringInput,
    RiskScoringTool,
    ScoringWeights,
    classify_risk_score,
)

pytestmark = pytest.mark.unit


def test_no_events_scores_zero() -> None:
    tool = RiskScoringTool()
    result = tool(RiskScoringInput(severity_counts={}, total_events=0, distinct_sources=0))
    assert result.risk_score == 0.0
    assert result.risk_label == Severity.INFO


def test_all_critical_events_scores_high() -> None:
    tool = RiskScoringTool()
    result = tool(
        RiskScoringInput(severity_counts={Severity.CRITICAL: 3}, total_events=3, distinct_sources=3)
    )
    # 3 * default critical weight (40.0) = 120, clamped to the 0-100 scale.
    assert result.risk_score == 100.0
    assert result.risk_label == Severity.CRITICAL


def test_score_clamped_at_100() -> None:
    tool = RiskScoringTool()
    result = tool(
        RiskScoringInput(
            severity_counts={Severity.CRITICAL: 10}, total_events=10, distinct_sources=10
        )
    )
    assert result.risk_score == 100.0


def test_source_concentration_adds_bonus() -> None:
    tool = RiskScoringTool()
    dispersed = tool(
        RiskScoringInput(severity_counts={Severity.LOW: 5}, total_events=5, distinct_sources=5)
    )
    concentrated = tool(
        RiskScoringInput(severity_counts={Severity.LOW: 5}, total_events=5, distinct_sources=1)
    )
    assert concentrated.risk_score > dispersed.risk_score


def test_deterministic_given_same_input() -> None:
    tool = RiskScoringTool()
    arguments = RiskScoringInput(
        severity_counts={Severity.MEDIUM: 2, Severity.HIGH: 1}, total_events=3, distinct_sources=2
    )
    first = tool(arguments)
    second = tool(arguments)
    assert first == second


def test_custom_weights_change_the_result() -> None:
    low_weights = ScoringWeights(critical=1.0, high=1.0, medium=1.0, low=1.0)
    high_weights = ScoringWeights(critical=90.0, high=90.0, medium=90.0, low=90.0)
    arguments = RiskScoringInput(
        severity_counts={Severity.HIGH: 1}, total_events=1, distinct_sources=1
    )
    low_result = RiskScoringTool(low_weights)(arguments)
    high_result = RiskScoringTool(high_weights)(arguments)
    assert high_result.risk_score > low_result.risk_score


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (5.0, Severity.LOW),
        (30.0, Severity.MEDIUM),
        (60.0, Severity.HIGH),
        (80.0, Severity.CRITICAL),
        (100.0, Severity.CRITICAL),
    ],
)
def test_classify_risk_score_buckets(score: float, expected: Severity) -> None:
    assert classify_risk_score(score) == expected
