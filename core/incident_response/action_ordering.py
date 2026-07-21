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
    ResponseCategory,
    ResponseEvidence,
    ResponsePhase,
    ResponseRecommendation,
    priority_rank,
)

#: Once a category has at least this many distinct-target recommendations
#: after the per-(category,target) merge below, they are consolidated into
#: one line item naming every target — task requirement: "produce concise
#: SOC-style action plans instead of repetitive lists." Below this count,
#: separate line items stay more useful than a consolidated one (an analyst
#: reading "Block network traffic: 203.0.113.44" and "...: 198.51.100.9" as
#: two lines is still concise; it's only once a category accumulates many
#: near-identical entries that a single consolidated action is clearer).
CONSOLIDATION_THRESHOLD = 3

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


def _consolidate(category_group: list[ResponseRecommendation]) -> ResponseRecommendation:
    """Merges every recommendation in `category_group` (already deduped by
    distinct target) into one consolidated line item — folding N
    near-identical "block traffic to/from indicator X" entries into a
    single "block traffic to/from N indicators: X, Y, Z" action, the same
    "merge similar remediation actions" the task asks for, applied once a
    category's target list has grown long enough that separate entries
    read as repetitive rather than informative."""
    winner = min(category_group, key=lambda r: priority_rank(r.priority))
    targets = [r.action.target for r in category_group if r.action.target]
    target_list = ", ".join(dict.fromkeys(targets)) if targets else ""

    merged_evidence: dict[tuple[str, str, str], ResponseEvidence] = {}
    merged_finding_ids: list[str] = []
    merged_technique_ids: list[str] = []
    for recommendation in category_group:
        for evidence in recommendation.required_evidence:
            merged_evidence.setdefault(
                (evidence.finding_id, evidence.source, evidence.description), evidence
            )
        merged_finding_ids.extend(recommendation.supporting_finding_ids)
        merged_technique_ids.extend(recommendation.mitre_technique_ids)

    base_title = winner.action.title.split(":", 1)[0]
    base_description = winner.action.description.split(" Target:", 1)[0]
    consolidated_action = winner.action.model_copy(
        update={
            "title": (
                f"{base_title} ({len(category_group)} indicators)" if target_list else base_title
            ),
            "description": (
                f"{base_description} Affects: {target_list}." if target_list else base_description
            ),
            "target": target_list,
        }
    )

    return winner.model_copy(
        update={
            "action": consolidated_action,
            "required_evidence": tuple(merged_evidence.values()),
            "supporting_finding_ids": tuple(dict.fromkeys(merged_finding_ids)),
            "mitre_technique_ids": tuple(dict.fromkeys(merged_technique_ids)),
            "risk_score": max(r.risk_score for r in category_group),
            "confidence": max(r.confidence for r in category_group),
            "rationale": (
                f"Consolidated from {len(category_group)} recommendations of the same "
                f"category (see individual finding IDs for provenance)."
            ),
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

    by_category: dict[ResponseCategory, list[ResponseRecommendation]] = {}
    for recommendation in deduped.values():
        by_category.setdefault(recommendation.action.category, []).append(recommendation)

    consolidated: list[ResponseRecommendation] = []
    for group in by_category.values():
        if len(group) >= CONSOLIDATION_THRESHOLD:
            consolidated.append(_consolidate(group))
        else:
            consolidated.extend(group)

    ordered = sorted(
        consolidated,
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
