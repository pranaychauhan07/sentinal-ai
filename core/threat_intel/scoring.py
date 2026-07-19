"""Threat Scoring Engine + Confidence Calculator — deterministic, pure
functions per constitution §1.9 ("Anything with one correct, checkable
answer ... is computed by a plain function, never by asking an LLM").
Weights are configurable (task requirement: "do not hardcode scoring
values"), defaulting to an even split, overridable via
`ScoringWeights`/`Settings.threat_intel_score_weight_*`.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.threat_intel.models import (
    IOCRecord,
    RuleMatchResult,
    SourceReliability,
    ThreatScore,
    ThreatSeverity,
)

#: `core.threat_intel.models.ThreatSeverity` -> a 0.0-1.0 weight, the input
#: `ThreatScoringEngine.score` folds into the composite score alongside the
#: other six dimensions.
SEVERITY_WEIGHTS: dict[ThreatSeverity, float] = {
    ThreatSeverity.INFO: 0.0,
    ThreatSeverity.LOW: 0.25,
    ThreatSeverity.MEDIUM: 0.5,
    ThreatSeverity.HIGH: 0.75,
    ThreatSeverity.CRITICAL: 1.0,
}

#: `core.threat_intel.models.SourceReliability` -> a 0.0-1.0 weight.
SOURCE_RELIABILITY_WEIGHTS: dict[SourceReliability, float] = {
    SourceReliability.UNKNOWN: 0.2,
    SourceReliability.LOW: 0.4,
    SourceReliability.MEDIUM: 0.6,
    SourceReliability.HIGH: 0.8,
    SourceReliability.CONFIRMED: 1.0,
}

#: Rule-match counts at or above this many matches saturate the
#: rule-match-score dimension at 1.0.
RULE_MATCH_SATURATION_COUNT = 3


class ScoringWeights(BaseModel):
    """Configurable weighting for each of the seven scoring dimensions the
    task requires. Must sum to 1.0 — validated so a misconfigured `.env`
    fails fast at settings-load time, not silently mis-scores every IOC."""

    model_config = ConfigDict(frozen=True)

    confidence: float = Field(default=1 / 7, ge=0.0, le=1.0)
    severity: float = Field(default=1 / 7, ge=0.0, le=1.0)
    impact: float = Field(default=1 / 7, ge=0.0, le=1.0)
    likelihood: float = Field(default=1 / 7, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=1 / 7, ge=0.0, le=1.0)
    source_reliability: float = Field(default=1 / 7, ge=0.0, le=1.0)
    rule_matches: float = Field(default=1 / 7, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> ScoringWeights:
        total = (
            self.confidence
            + self.severity
            + self.impact
            + self.likelihood
            + self.evidence_quality
            + self.source_reliability
            + self.rule_matches
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"ScoringWeights must sum to 1.0, got {total!r}.")
        return self


class ConfidenceCalculator:
    """Deterministic combination of extraction confidence, validation
    outcome, rule-match count, and source reliability into one 0.0-1.0
    confidence value — kept as its own small class (constitution §1.3:
    "small, focused modules") rather than inlined into the scoring engine,
    since a future agent may need confidence alone without a full score."""

    def calculate(
        self,
        *,
        extraction_confidence: float,
        validation_passed: bool,
        rule_match_count: int,
        source_reliability: SourceReliability,
    ) -> float:
        if not validation_passed:
            return 0.0
        rule_boost = (
            min(rule_match_count, RULE_MATCH_SATURATION_COUNT) / RULE_MATCH_SATURATION_COUNT
        )
        reliability_weight = SOURCE_RELIABILITY_WEIGHTS[source_reliability]
        combined = 0.5 * extraction_confidence + 0.3 * rule_boost + 0.2 * reliability_weight
        return max(0.0, min(1.0, combined))


class ThreatScoringEngine:
    """Computes the composite `ThreatScore` for one `IOCRecord`, folding in
    its rule matches, evidence quality, and source reliability."""

    def __init__(self, *, weights: ScoringWeights | None = None) -> None:
        self._weights = weights or ScoringWeights()

    def score(
        self,
        ioc: IOCRecord,
        *,
        rule_matches: list[RuleMatchResult],
        evidence_quality: float,
        source_reliability: SourceReliability,
    ) -> ThreatScore:
        severity_weight = SEVERITY_WEIGHTS[ioc.severity]
        reliability_weight = SOURCE_RELIABILITY_WEIGHTS[source_reliability]
        rule_match_score = (
            min(len(rule_matches), RULE_MATCH_SATURATION_COUNT) / RULE_MATCH_SATURATION_COUNT
        )
        impact = severity_weight
        likelihood = min(1.0, 0.5 * ioc.confidence + 0.5 * rule_match_score)
        evidence_quality_clamped = max(0.0, min(1.0, evidence_quality))

        composite_fraction = (
            self._weights.confidence * ioc.confidence
            + self._weights.severity * severity_weight
            + self._weights.impact * impact
            + self._weights.likelihood * likelihood
            + self._weights.evidence_quality * evidence_quality_clamped
            + self._weights.source_reliability * reliability_weight
            + self._weights.rule_matches * rule_match_score
        )

        return ThreatScore(
            confidence=ioc.confidence,
            severity_weight=severity_weight,
            impact=impact,
            likelihood=likelihood,
            evidence_quality=evidence_quality_clamped,
            source_reliability=reliability_weight,
            rule_match_score=rule_match_score,
            composite_score=round(max(0.0, min(100.0, composite_fraction * 100.0)), 2),
        )
