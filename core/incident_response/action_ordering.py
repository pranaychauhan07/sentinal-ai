"""`order_recommendations` — deduplicates recommendations that resolved to
the same category+target from different findings, then assigns a
deterministic, reproducible `execution_order` (task requirement: "Suggested
execution order" per recommendation; "Plans must be deterministic and
reproducible").

Sort key, in fixed precedence order:

1. `ResponsePriority` rank (P1 first).
2. `ResponsePhase` in NIST-lifecycle order (containment before isolation
   before eradication before recovery before validation before
   post-incident) — the task's exact named phase list, in that order.
3. `risk_score` descending (the higher-risk finding's recommendation sorts
   first within the same priority/phase).
4. `ResponseCategory` value (alphabetical) — the final, purely mechanical
   tie-break that guarantees a stable order for otherwise-identical
   recommendations, independent of input iteration order (constitution §5,
   "Deterministic outputs").
"""

from __future__ import annotations

from core.incident_response.models import (
    ResponseEvidence,
    ResponsePhase,
    ResponseRecommendation,
    priority_rank,
)

#: NIST SP 800-61-aligned phase precedence — index is the sort rank.
_PHASE_ORDER: tuple[ResponsePhase, ...] = (
    ResponsePhase.CONTAINMENT,
    ResponsePhase.ISOLATION,
    ResponsePhase.ERADICATION,
    ResponsePhase.RECOVERY,
    ResponsePhase.VALIDATION,
    ResponsePhase.POST_INCIDENT,
)
_PHASE_RANK: dict[ResponsePhase, int] = {phase: i for i, phase in enumerate(_PHASE_ORDER)}


def _dedup_key(recommendation: ResponseRecommendation) -> tuple[str, str]:
    return (recommendation.action.category.value, recommendation.action.target)


def _merge(first: ResponseRecommendation, second: ResponseRecommendation) -> ResponseRecommendation:
    """Merges two recommendations that resolved to the same
    (category, target) — the more urgent priority and higher risk score
    win; evidence/supporting-finding/MITRE-technique lists are unioned,
    order-preserving, never silently dropping either side's provenance."""
    first_is_more_urgent = priority_rank(first.priority) <= priority_rank(second.priority)
    winner, loser = (first, second) if first_is_more_urgent else (second, first)
    merged_evidence: dict[tuple[str, str, str], ResponseEvidence] = {}
    for evidence in (*winner.required_evidence, *loser.required_evidence):
        merged_evidence.setdefault(
            (evidence.finding_id, evidence.source, evidence.description), evidence
        )
    merged_finding_ids = tuple(
        dict.fromkeys((*winner.supporting_finding_ids, *loser.supporting_finding_ids))
    )
    merged_technique_ids = tuple(
        dict.fromkeys((*winner.mitre_technique_ids, *loser.mitre_technique_ids))
    )
    return winner.model_copy(
        update={
            "required_evidence": tuple(merged_evidence.values()),
            "supporting_finding_ids": merged_finding_ids,
            "mitre_technique_ids": merged_technique_ids,
            "risk_score": max(winner.risk_score, loser.risk_score),
            "confidence": max(winner.confidence, loser.confidence),
        }
    )


def order_recommendations(
    recommendations: list[ResponseRecommendation],
) -> tuple[ResponseRecommendation, ...]:
    deduped: dict[tuple[str, str], ResponseRecommendation] = {}
    for recommendation in recommendations:
        key = _dedup_key(recommendation)
        if key in deduped:
            deduped[key] = _merge(deduped[key], recommendation)
        else:
            deduped[key] = recommendation

    ordered = sorted(
        deduped.values(),
        key=lambda r: (
            priority_rank(r.priority),
            _PHASE_RANK[r.action.phase],
            -r.risk_score,
            r.action.category.value,
        ),
    )
    return tuple(
        recommendation.model_copy(update={"execution_order": index})
        for index, recommendation in enumerate(ordered, start=1)
    )
