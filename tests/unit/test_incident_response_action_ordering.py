"""Unit tests for core/incident_response/action_ordering.py."""

from __future__ import annotations

import pytest

from core.incident_response.action_ordering import order_recommendations
from core.incident_response.models import (
    ResponseAction,
    ResponseCategory,
    ResponsePhase,
    ResponsePriority,
    ResponseRecommendation,
    ResponseTimeframe,
)

pytestmark = pytest.mark.unit


def _recommendation(
    *,
    category: ResponseCategory = ResponseCategory.HOST_ISOLATION,
    phase: ResponsePhase = ResponsePhase.ISOLATION,
    priority: ResponsePriority = ResponsePriority.P1_IMMEDIATE,
    target: str = "",
    risk_score: float = 50.0,
    finding_id: str = "f1",
) -> ResponseRecommendation:
    return ResponseRecommendation(
        action=ResponseAction(
            category=category, phase=phase, title="t", description="d", target=target
        ),
        timeframe=ResponseTimeframe.IMMEDIATE,
        priority=priority,
        confidence=0.9,
        supporting_finding_ids=(finding_id,),
        risk_score=risk_score,
        execution_order=1,
    )


def test_execution_order_is_assigned_starting_at_one() -> None:
    ordered = order_recommendations([_recommendation(), _recommendation(target="host-2")])
    assert [r.execution_order for r in ordered] == [1, 2]


def test_higher_priority_sorts_before_lower_priority() -> None:
    urgent = _recommendation(priority=ResponsePriority.P1_IMMEDIATE, target="a")
    low = _recommendation(priority=ResponsePriority.P5_LOW, target="b")
    ordered = order_recommendations([low, urgent])
    assert ordered[0].action.target == "a"
    assert ordered[1].action.target == "b"


def test_phase_breaks_ties_within_same_priority() -> None:
    containment = _recommendation(
        phase=ResponsePhase.CONTAINMENT, priority=ResponsePriority.P2_URGENT, target="a"
    )
    recovery = _recommendation(
        phase=ResponsePhase.RECOVERY, priority=ResponsePriority.P2_URGENT, target="b"
    )
    ordered = order_recommendations([recovery, containment])
    assert ordered[0].action.phase == ResponsePhase.CONTAINMENT
    assert ordered[1].action.phase == ResponsePhase.RECOVERY


def test_duplicate_category_and_target_are_merged_not_duplicated() -> None:
    first = _recommendation(target="host-1", finding_id="f1")
    second = _recommendation(target="host-1", finding_id="f2")
    ordered = order_recommendations([first, second])
    assert len(ordered) == 1
    assert set(ordered[0].supporting_finding_ids) == {"f1", "f2"}


def test_merge_keeps_more_urgent_priority_and_higher_risk_score() -> None:
    urgent = _recommendation(
        target="host-1", priority=ResponsePriority.P1_IMMEDIATE, risk_score=40.0
    )
    less_urgent_but_riskier = _recommendation(
        target="host-1", priority=ResponsePriority.P4_MEDIUM, risk_score=90.0
    )
    ordered = order_recommendations([less_urgent_but_riskier, urgent])
    assert len(ordered) == 1
    assert ordered[0].priority == ResponsePriority.P1_IMMEDIATE
    assert ordered[0].risk_score == 90.0


def test_different_targets_stay_separate_recommendations() -> None:
    ordered = order_recommendations(
        [_recommendation(target="host-1"), _recommendation(target="host-2")]
    )
    assert len(ordered) == 2


def test_empty_input_returns_empty_output() -> None:
    assert order_recommendations([]) == ()


# --- Consolidation (task requirement: "concise SOC-style action plans
# instead of repetitive lists") --------------------------------------------


def test_two_distinct_targets_stay_separate_below_consolidation_threshold() -> None:
    ordered = order_recommendations(
        [_recommendation(target="1.1.1.1"), _recommendation(target="2.2.2.2")]
    )
    assert len(ordered) == 2


def test_three_or_more_same_category_recommendations_consolidate_into_one() -> None:
    recommendations = [
        _recommendation(target=f"10.0.0.{i}", finding_id=f"f{i}", risk_score=float(i * 10))
        for i in range(1, 5)
    ]
    ordered = order_recommendations(recommendations)
    assert len(ordered) == 1
    consolidated = ordered[0]
    assert "4 indicators" in consolidated.action.title
    for i in range(1, 5):
        assert f"10.0.0.{i}" in consolidated.action.target
    assert set(consolidated.supporting_finding_ids) == {"f1", "f2", "f3", "f4"}
    assert consolidated.risk_score == 40.0  # max across the group


def test_consolidation_only_merges_within_the_same_category() -> None:
    isolation_recs = [
        _recommendation(
            category=ResponseCategory.HOST_ISOLATION,
            phase=ResponsePhase.ISOLATION,
            target=f"host-{i}",
            finding_id=f"f{i}",
        )
        for i in range(3)
    ]
    network_rec = _recommendation(
        category=ResponseCategory.NETWORK_BLOCKING,
        phase=ResponsePhase.CONTAINMENT,
        target="1.2.3.4",
        finding_id="f-net",
    )
    ordered = order_recommendations([*isolation_recs, network_rec])
    categories = {r.action.category for r in ordered}
    assert categories == {ResponseCategory.HOST_ISOLATION, ResponseCategory.NETWORK_BLOCKING}
    assert len(ordered) == 2  # 3 isolation recs -> 1 consolidated + 1 untouched network rec
