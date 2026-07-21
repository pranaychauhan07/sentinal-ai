"""`RiskPrioritizer` — turns one matched `(finding, ResponseCategory)` pair
into a fully-specified `ResponseRecommendation` (minus `execution_order`,
which `action_ordering.py` assigns once every recommendation for the case
exists). Pure, deterministic (constitution §1.9): given the same finding and
category, always produces the same priority/confidence/risk score.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import (
    IncidentSeverity,
    ResponseCategory,
    ResponseEvidence,
    ResponsePriority,
    ResponseRecommendation,
    priority_rank,
)
from core.incident_response.playbook_rules import CATEGORY_TEMPLATES, build_action

#: `ResponsePriority` values in rank order, index == rank (0 = most urgent)
#: — used to escalate/de-escalate a category's base priority by finding
#: severity without hardcoding the enum ordering twice.
_PRIORITY_BY_RANK: tuple[ResponsePriority, ...] = (
    ResponsePriority.P1_IMMEDIATE,
    ResponsePriority.P2_URGENT,
    ResponsePriority.P3_HIGH,
    ResponsePriority.P4_MEDIUM,
    ResponsePriority.P5_LOW,
)

#: Default risk score assigned when the triggering finding carried no
#: `risk_score` of its own (a 0.0 default from `IncidentInputFinding`,
#: distinct from a genuine, computed zero) — a severity-only estimate,
#: mirroring `core.tools.scoring.classify_risk_score`'s bucket midpoints in
#: reverse.
_SEVERITY_DEFAULT_RISK_SCORE: dict[IncidentSeverity, float] = {
    IncidentSeverity.CRITICAL: 90.0,
    IncidentSeverity.HIGH: 70.0,
    IncidentSeverity.MEDIUM: 45.0,
    IncidentSeverity.LOW: 20.0,
    IncidentSeverity.INFO: 5.0,
}


class PrioritizationWeights(BaseModel):
    """Configurable severity-driven priority escalation
    (constitution §2, "do not hardcode scoring values")."""

    model_config = ConfigDict(frozen=True)

    #: Rank steps to escalate (toward P1) for a CRITICAL-severity finding.
    critical_escalation_steps: int = Field(default=1, ge=0)
    #: Rank steps to de-escalate (toward P5) for a LOW/INFO-severity finding.
    low_deescalation_steps: int = Field(default=1, ge=0)


class RiskPrioritizer:
    def __init__(self, *, weights: PrioritizationWeights | None = None) -> None:
        self._weights = weights or PrioritizationWeights()

    def prioritize(
        self, finding: IncidentInputFinding, category: ResponseCategory
    ) -> ResponseRecommendation:
        template = CATEGORY_TEMPLATES[category]
        action = build_action(finding, category)

        base_rank = priority_rank(template.base_priority)
        if finding.severity is IncidentSeverity.CRITICAL:
            rank = max(0, base_rank - self._weights.critical_escalation_steps)
        elif finding.severity in (IncidentSeverity.LOW, IncidentSeverity.INFO):
            rank = min(len(_PRIORITY_BY_RANK) - 1, base_rank + self._weights.low_deescalation_steps)
        else:
            rank = base_rank
        priority = _PRIORITY_BY_RANK[rank]

        risk_score = (
            finding.risk_score
            if finding.risk_score > 0.0
            else _SEVERITY_DEFAULT_RISK_SCORE[finding.severity]
        )

        required_evidence = (
            ResponseEvidence(
                finding_id=finding.finding_id,
                source=finding.source,
                description=finding.title or f"{finding.source} finding {finding.finding_id}",
            ),
        )

        rationale = (
            f"Triggered by {finding.severity.value}-severity finding "
            f"'{finding.title or finding.finding_id}' from {finding.source or 'an unknown source'}."
        )

        return ResponseRecommendation(
            action=action,
            timeframe=template.timeframe,
            priority=priority,
            confidence=finding.confidence,
            required_evidence=required_evidence,
            supporting_finding_ids=(finding.finding_id,) if finding.finding_id else (),
            mitre_technique_ids=finding.mitre_technique_ids,
            risk_score=risk_score,
            expected_impact=template.expected_impact,
            rationale=rationale,
            execution_order=1,  # placeholder — reassigned by action_ordering.py
        )
