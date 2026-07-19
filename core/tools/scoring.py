"""`RiskScoringTool` — the "single source of truth" risk-scoring math
blueprint §10 calls for ("`scoring.py` is intentionally the *one* place this
math lives"). Scoped to the SOC Analyst Agent's raw-evidence risk assessment
(blueprint §7: "Tools used: log_tools.py, scoring.py") — distinct from, and
never duplicating, `core/findings/severity.py`'s `calculate_risk_score`,
which scores an already MITRE-mapped `FindingRecord` downstream of IOC
extraction. This tool scores a artifact's evidence records directly, before
any IOC/Finding exists, matching constitution §1.9: deterministic, no LLM
arithmetic.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.parsers.models import Severity
from core.tools.base import BaseTool

#: Deterministic bucket cut points, mirroring
#: `core.agents.confidence.classify_confidence`'s "hardcoded, never
#: settings-driven" pattern — thresholds are a stable scale, not a tunable
#: weight (weights below *are* configurable).
_CRITICAL_THRESHOLD = 80.0
_HIGH_THRESHOLD = 60.0
_MEDIUM_THRESHOLD = 30.0
_LOW_THRESHOLD = 1.0


class ScoringWeights(BaseModel):
    """Configurable coefficients for :class:`RiskScoringTool`
    (constitution §2, "Constants" + the project's established
    "do not hardcode scoring values" convention, matching
    `core.findings.confidence_engine.FindingConfidenceWeights`'s shape).
    Unlike that class's weights, these are not required to sum to 1.0 — they
    are independent linear coefficients on a 0-100 scale, clamped at the
    tool boundary.
    """

    model_config = ConfigDict(frozen=True)

    critical: float = Field(default=40.0, ge=0.0)
    high: float = Field(default=22.0, ge=0.0)
    medium: float = Field(default=10.0, ge=0.0)
    low: float = Field(default=3.0, ge=0.0)
    info: float = Field(default=0.0, ge=0.0)
    #: Bonus applied when many events concentrate on few distinct sources
    #: (a brute-force-shaped signal), capped by `concentration_cap`.
    concentration_weight: float = Field(default=5.0, ge=0.0)
    concentration_cap: float = Field(default=20.0, ge=0.0)

    def weight_for(self, severity: Severity) -> float:
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.medium,
            Severity.LOW: self.low,
            Severity.INFO: self.info,
        }[severity]


class RiskScoringInput(BaseModel):
    """One evidence artifact's aggregate signal — counts only, never raw
    event content (the tool is a pure aggregator, not a re-parser)."""

    model_config = ConfigDict(frozen=True)

    severity_counts: dict[Severity, int] = Field(default_factory=dict)
    total_events: int = Field(ge=0)
    distinct_sources: int = Field(ge=0)


class RiskScoringOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    risk_score: float = Field(ge=0.0, le=100.0)
    risk_label: Severity


def classify_risk_score(value: float) -> Severity:
    """Pure, deterministic bucketing — never computed by an LLM
    (constitution §1.9), mirroring `core.agents.confidence.classify_confidence`."""
    if value >= _CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if value >= _HIGH_THRESHOLD:
        return Severity.HIGH
    if value >= _MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    if value >= _LOW_THRESHOLD:
        return Severity.LOW
    return Severity.INFO


class RiskScoringTool(BaseTool[RiskScoringInput, RiskScoringOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output (constitution §5,
    "Deterministic outputs")."""

    name: ClassVar[str] = "risk_scoring"
    description: ClassVar[str] = (
        "Computes a 0-100 risk score and severity label from an evidence "
        "artifact's aggregate severity distribution and source concentration."
    )
    is_io_bound: ClassVar[bool] = False

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        super().__init__()
        self._weights = weights or ScoringWeights()

    def run(self, arguments: RiskScoringInput) -> RiskScoringOutput:
        base = sum(
            self._weights.weight_for(severity) * count
            for severity, count in arguments.severity_counts.items()
        )
        concentration_bonus = 0.0
        if arguments.distinct_sources > 0 and arguments.total_events > arguments.distinct_sources:
            concentration_ratio = arguments.total_events / arguments.distinct_sources
            concentration_bonus = min(
                self._weights.concentration_cap,
                (concentration_ratio - 1.0) * self._weights.concentration_weight,
            )
        risk_score = max(0.0, min(100.0, base + concentration_bonus))
        return RiskScoringOutput(risk_score=risk_score, risk_label=classify_risk_score(risk_score))
