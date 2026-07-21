"""`ResponsePlanEngine` — the task's named pipeline orchestrator:

    findings (already collected/classified by the caller)
        -> prioritize risks (severity classification)
        -> generate response actions (playbook rule matching)
        -> order execution (dedup + sort + execution_order)
        -> calculate confidence (plan-level rollup)
        -> build IncidentResponsePlan

"Collect Findings" / "Collect Threat Intelligence" / "Collect MITRE Mapping"
(the pipeline's first three named stages) are deliberately **not** this
engine's job — those already-computed values are what
`core.agents.incident_response_agent.IncidentResponseAgent` hands in as
`IncidentInputFinding` (docs/adr/0023-incident-response-agent.md, Decision
1); this engine never re-derives a severity, a risk score, or a MITRE
mapping itself (constitution §1.9). "Publish Events" / "Persist Response
Plan" (the pipeline's last two named stages) are likewise not this engine's
job — publishing/persistence are `core/services`/`core/db` concerns; this
engine returns a plain `IncidentResponsePlan` value.
"""

from __future__ import annotations

from core.incident_response.action_ordering import order_recommendations
from core.incident_response.audit import (
    AuditAction,
    log_incident_response_audit_event,
    timed_execution,
)
from core.incident_response.confidence_calculator import (
    calculate_plan_confidence,
    calculate_plan_risk_score,
)
from core.incident_response.exceptions import OversizedFindingSetError
from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.metrics import IncidentResponseMetricsCollector
from core.incident_response.models import (
    IncidentResponsePlan,
    IncidentSeverity,
    ResponseCategory,
    ResponseMetrics,
    ResponseRecommendation,
)
from core.incident_response.playbook_rules import match_categories
from core.incident_response.risk_prioritizer import PrioritizationWeights, RiskPrioritizer
from core.incident_response.severity_classifier import (
    IncidentSeverityClassifier,
    SeverityClassificationWeights,
)

#: Lessons-learned templates, keyed by the category(ies) that trigger them —
#: deterministic, static text (task requirement: "No LLM reasoning"), never
#: freeform-generated.
_LESSON_TEMPLATES: tuple[tuple[frozenset[ResponseCategory], str], ...] = (
    (
        frozenset({ResponseCategory.HOST_ISOLATION, ResponseCategory.SERVICE_SHUTDOWN}),
        "Document isolation/shutdown execution time and confirm asset-inventory accuracy "
        "for the affected system(s), to reduce containment latency next time.",
    ),
    (
        frozenset({ResponseCategory.PATCH_PRIORITIZATION}),
        "Incorporate the underlying vulnerability into the next vulnerability-management "
        "cycle's root-cause review.",
    ),
    (
        frozenset({ResponseCategory.ACCOUNT_DISABLEMENT, ResponseCategory.PASSWORD_RESET}),
        "Review credential policy (MFA enforcement, password rotation cadence) for "
        "accounts implicated in this incident.",
    ),
    (
        frozenset(
            {
                ResponseCategory.NETWORK_BLOCKING,
                ResponseCategory.FIREWALL_UPDATE,
                ResponseCategory.IOC_BLOCKING,
            }
        ),
        "Assess whether the network/firewall rules implicated in this incident should be "
        "tightened permanently, not just for the duration of this case.",
    ),
    (
        frozenset({ResponseCategory.BACKUP_RESTORATION}),
        "Verify backup recency and restoration time actually met this incident's recovery "
        "objectives; adjust backup cadence if it did not.",
    ),
)

_ALWAYS_ON_LESSON = (
    "Update this case's post-incident review with root cause, timeline accuracy, and "
    "control gaps once containment and eradication are confirmed complete."
)


def _build_metrics(
    recommendations: tuple[ResponseRecommendation, ...],
    *,
    finding_count: int,
    duplicate_count: int,
    duration_ms: float,
) -> ResponseMetrics:
    by_phase: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    by_category: dict[str, int] = {}
    technique_ids: set[str] = set()
    for recommendation in recommendations:
        by_phase[recommendation.action.phase.value] = (
            by_phase.get(recommendation.action.phase.value, 0) + 1
        )
        by_priority[recommendation.priority.value] = (
            by_priority.get(recommendation.priority.value, 0) + 1
        )
        by_category[recommendation.action.category.value] = (
            by_category.get(recommendation.action.category.value, 0) + 1
        )
        technique_ids.update(recommendation.mitre_technique_ids)

    average_confidence = (
        round(sum(r.confidence for r in recommendations) / len(recommendations), 4)
        if recommendations
        else 0.0
    )
    highest_risk_score = max((r.risk_score for r in recommendations), default=0.0)

    return ResponseMetrics(
        total_recommendations=len(recommendations),
        recommendations_by_phase=by_phase,
        recommendations_by_priority=by_priority,
        recommendations_by_category=by_category,
        average_confidence=average_confidence,
        highest_risk_score=highest_risk_score,
        finding_count_considered=finding_count,
        mitre_technique_count=len(technique_ids),
        generation_duration_ms=round(duration_ms, 3),
    )


def _build_lessons_learned(recommendations: tuple[ResponseRecommendation, ...]) -> tuple[str, ...]:
    if not recommendations:
        return ()
    triggered_categories = {r.action.category for r in recommendations}
    lessons = [text for categories, text in _LESSON_TEMPLATES if triggered_categories & categories]
    lessons.append(_ALWAYS_ON_LESSON)
    return tuple(lessons)


class ResponsePlanEngine:
    """Deterministic, no-I/O (constitution §5) — given the same
    `IncidentInputFinding` list, always returns the same
    `IncidentResponsePlan` (modulo `plan_id`/`generated_at`, which are
    identity/provenance fields, not planning output)."""

    def __init__(
        self,
        *,
        max_findings_per_plan: int = 5_000,
        severity_weights: SeverityClassificationWeights | None = None,
        prioritization_weights: PrioritizationWeights | None = None,
        metrics: IncidentResponseMetricsCollector | None = None,
    ) -> None:
        self._max_findings_per_plan = max_findings_per_plan
        self._severity_classifier = IncidentSeverityClassifier(weights=severity_weights)
        self._prioritizer = RiskPrioritizer(weights=prioritization_weights)
        self._metrics = metrics or IncidentResponseMetricsCollector()

    def generate(
        self,
        *,
        case_id: str,
        findings: list[IncidentInputFinding],
        skipped_record_count: int = 0,
    ) -> IncidentResponsePlan:
        if len(findings) > self._max_findings_per_plan:
            log_incident_response_audit_event(
                action=AuditAction.OVERSIZED_FINDING_SET_REJECTED,
                case_id=case_id,
                detail=f"{len(findings)} findings exceeds max {self._max_findings_per_plan}.",
            )
            raise OversizedFindingSetError(
                f"{len(findings)} findings exceeds the configured maximum of "
                f"{self._max_findings_per_plan} for a single plan generation.",
                details={"case_id": case_id, "finding_count": len(findings)},
            )

        with timed_execution("generate_plan") as timing:
            if not findings:
                plan = IncidentResponsePlan(
                    case_id=case_id,
                    incident_severity=IncidentSeverity.INFO,
                    overall_risk_score=0.0,
                    overall_confidence=0.0,
                    recommendations=(),
                    lessons_learned=(),
                    metrics=_build_metrics((), finding_count=0, duplicate_count=0, duration_ms=0.0),
                    plan_degraded=True,
                    degraded_reason=(
                        "No findings available for this case yet; insufficient evidence to "
                        "generate a response plan (not the same as 'no incident')."
                    ),
                )
                log_incident_response_audit_event(
                    action=AuditAction.PLAN_DEGRADED, case_id=case_id, detail=plan.degraded_reason
                )
                return plan

            incident_severity = self._severity_classifier.classify(findings)

            raw_recommendations: list[ResponseRecommendation] = []
            for finding in findings:
                self._metrics.record_finding_considered()
                categories = match_categories(finding)
                for category in categories:
                    recommendation = self._prioritizer.prioritize(finding, category)
                    raw_recommendations.append(recommendation)
                    self._metrics.record_recommendation_generated()
                    log_incident_response_audit_event(
                        action=AuditAction.RECOMMENDATION_GENERATED,
                        case_id=case_id,
                        category=category.value,
                        detail=f"finding_id={finding.finding_id or 'unknown'}",
                    )

            ordered = order_recommendations(raw_recommendations)
            duplicate_count = len(raw_recommendations) - len(ordered)
            if duplicate_count > 0:
                self._metrics.record_recommendations_deduplicated(duplicate_count)
                log_incident_response_audit_event(
                    action=AuditAction.RECOMMENDATIONS_MERGED,
                    case_id=case_id,
                    detail=f"{duplicate_count} duplicate recommendation(s) merged.",
                )

            overall_confidence = calculate_plan_confidence(
                ordered,
                skipped_record_count=skipped_record_count,
                considered_record_count=len(findings),
            )
            overall_risk_score = calculate_plan_risk_score(ordered)
            lessons_learned = _build_lessons_learned(ordered)

        metrics = _build_metrics(
            ordered,
            finding_count=len(findings),
            duplicate_count=duplicate_count,
            duration_ms=timing["duration_ms"],
        )
        self._metrics.record_processing_time(timing["duration_ms"])

        plan_degraded = not ordered
        plan = IncidentResponsePlan(
            case_id=case_id,
            incident_severity=incident_severity,
            overall_risk_score=overall_risk_score,
            overall_confidence=overall_confidence,
            recommendations=ordered,
            lessons_learned=lessons_learned,
            metrics=metrics,
            plan_degraded=plan_degraded,
            degraded_reason=(
                "Findings were present but none matched a response category."
                if plan_degraded
                else ""
            ),
        )
        log_incident_response_audit_event(
            action=AuditAction.PLAN_GENERATED,
            case_id=case_id,
            detail=f"{len(ordered)} recommendation(s), severity={incident_severity.value}.",
        )
        return plan
