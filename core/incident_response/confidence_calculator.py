"""`calculate_plan_confidence`/`calculate_plan_risk_score` — the case-level
rollups `IncidentResponsePlan.overall_confidence`/`overall_risk_score` are
built from. Pure, deterministic (constitution §1.9) — never recomputed
ad hoc anywhere else in this package.
"""

from __future__ import annotations

from core.incident_response.models import ResponseRecommendation


def calculate_plan_confidence(
    recommendations: tuple[ResponseRecommendation, ...],
    *,
    skipped_record_count: int,
    considered_record_count: int,
) -> float:
    """Mean confidence across every recommendation, discounted by the
    fraction of input records that were malformed/skipped — a plan built
    from a case where half the findings could not be parsed is genuinely
    less trustworthy than one built from clean input, and that must be
    visible in the number, not just a log line."""
    if not recommendations:
        return 0.0
    mean_confidence = sum(r.confidence for r in recommendations) / len(recommendations)
    total = considered_record_count + skipped_record_count
    if total == 0:
        return round(mean_confidence, 4)
    clean_fraction = considered_record_count / total
    return round(mean_confidence * clean_fraction, 4)


def calculate_plan_risk_score(recommendations: tuple[ResponseRecommendation, ...]) -> float:
    """The plan's overall risk score is its single highest-risk
    recommendation's score — a plan is only as safe as its most severe
    open driver, never diluted by averaging against many low-risk items."""
    if not recommendations:
        return 0.0
    return max(r.risk_score for r in recommendations)
