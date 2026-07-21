"""Unit tests for core/incident_response/models.py."""

from __future__ import annotations

import pytest

from core.incident_response.models import (
    IncidentResponsePlan,
    IncidentSeverity,
    ResponseAction,
    ResponseCategory,
    ResponsePhase,
    ResponsePriority,
    ResponseRecommendation,
    ResponseTimeframe,
    highest_severity,
    priority_rank,
    severity_rank,
)

pytestmark = pytest.mark.unit


def test_severity_rank_orders_critical_highest() -> None:
    assert severity_rank(IncidentSeverity.CRITICAL) > severity_rank(IncidentSeverity.INFO)


def test_highest_severity_of_empty_list_is_info() -> None:
    assert highest_severity([]) == IncidentSeverity.INFO


def test_highest_severity_picks_the_max() -> None:
    assert (
        highest_severity([IncidentSeverity.LOW, IncidentSeverity.CRITICAL, IncidentSeverity.MEDIUM])
        == IncidentSeverity.CRITICAL
    )


def test_priority_rank_p1_is_most_urgent() -> None:
    assert priority_rank(ResponsePriority.P1_IMMEDIATE) < priority_rank(ResponsePriority.P5_LOW)


def _recommendation(
    phase: ResponsePhase, timeframe: ResponseTimeframe, order: int
) -> ResponseRecommendation:
    return ResponseRecommendation(
        action=ResponseAction(
            category=ResponseCategory.HOST_ISOLATION, phase=phase, title="t", description="d"
        ),
        timeframe=timeframe,
        priority=ResponsePriority.P1_IMMEDIATE,
        confidence=1.0,
        risk_score=50.0,
        execution_order=order,
    )


def test_plan_phase_groupings_are_derived_not_duplicated() -> None:
    plan = IncidentResponsePlan(
        case_id="c1",
        incident_severity=IncidentSeverity.HIGH,
        overall_risk_score=50.0,
        overall_confidence=0.9,
        recommendations=(
            _recommendation(ResponsePhase.CONTAINMENT, ResponseTimeframe.IMMEDIATE, 1),
            _recommendation(ResponsePhase.RECOVERY, ResponseTimeframe.SHORT_TERM, 2),
        ),
    )
    assert len(plan.containment_actions) == 1
    assert len(plan.recovery_actions) == 1
    assert len(plan.isolation_actions) == 0
    assert len(plan.immediate_actions) == 1
    assert len(plan.short_term_remediation) == 1
    assert len(plan.long_term_hardening) == 0
