"""`IncidentSeverityClassifier` — derives this case's overall
`IncidentSeverity` from its normalized findings. Pure, deterministic
(constitution §1.9): never an LLM guess, always the same output for the
same input.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity, highest_severity, severity_rank

#: Highest severity rank ("critical" = 4, see `models.severity_rank`).
_MAX_RANK = severity_rank(IncidentSeverity.CRITICAL)


class SeverityClassificationWeights(BaseModel):
    """Configurable escalation thresholds (constitution §2, "do not hardcode
    scoring values"). A case whose highest single finding is only MEDIUM can
    still classify as HIGH/CRITICAL overall once enough MEDIUM-or-above
    findings corroborate each other — the same "concentration" idea
    `core.tools.scoring.RiskScoringTool` already applies to raw evidence,
    applied here to a case's aggregated findings instead."""

    model_config = ConfigDict(frozen=True)

    #: Count of MEDIUM-or-above findings that escalates the overall
    #: classification by one severity level (capped at CRITICAL).
    escalation_finding_count: int = Field(default=3, ge=1)
    #: A second escalation step once this many findings qualify.
    double_escalation_finding_count: int = Field(default=6, ge=1)


class IncidentSeverityClassifier:
    def __init__(self, *, weights: SeverityClassificationWeights | None = None) -> None:
        self._weights = weights or SeverityClassificationWeights()

    def classify(self, findings: list[IncidentInputFinding]) -> IncidentSeverity:
        if not findings:
            return IncidentSeverity.INFO

        base = highest_severity([f.severity for f in findings])
        qualifying = sum(
            1
            for f in findings
            if severity_rank(f.severity) >= severity_rank(IncidentSeverity.MEDIUM)
        )

        escalation_steps = 0
        if qualifying >= self._weights.double_escalation_finding_count:
            escalation_steps = 2
        elif qualifying >= self._weights.escalation_finding_count:
            escalation_steps = 1

        target_rank = min(_MAX_RANK, severity_rank(base) + escalation_steps)
        for candidate in IncidentSeverity:
            if severity_rank(candidate) == target_rank:
                return candidate
        return base  # pragma: no cover - every rank has a candidate by construction
