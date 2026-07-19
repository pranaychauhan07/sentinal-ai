"""`ConfidenceEngine` — deterministic, configurable combination of all seven
required Finding-confidence dimensions (constitution §1.9: "one correct,
checkable answer" work, never an LLM guess). Weights are configurable (task
requirement: "do not hardcode scoring values"), mirroring
`core.threat_intel.scoring.ScoringWeights`'s "must sum to 1.0" pattern
exactly.

`_SOURCE_RELIABILITY_WEIGHTS` intentionally duplicates
`core.threat_intel.scoring.SOURCE_RELIABILITY_WEIGHTS`'s values rather than
importing that module: `core/findings`'s documented sideways-leaf-model
exception (docs/adr/0013 point 2) covers `core.threat_intel.models` only,
not `core.threat_intel.scoring` — this small, explicit constant keeps that
boundary honest instead of reaching past it for convenience.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.findings.models import FindingConfidence, MitreMapping
from core.threat_intel.models import ScoredIOC, SourceReliability

_SOURCE_RELIABILITY_WEIGHTS: dict[SourceReliability, float] = {
    SourceReliability.UNKNOWN: 0.2,
    SourceReliability.LOW: 0.4,
    SourceReliability.MEDIUM: 0.6,
    SourceReliability.HIGH: 0.8,
    SourceReliability.CONFIRMED: 1.0,
}

#: Supporting-indicator counts at or above this many IOCs saturate the
#: `supporting_indicator_score` dimension at 1.0.
SUPPORTING_INDICATOR_SATURATION_COUNT = 5

#: Neutral placeholder for the `historical_evidence` dimension — no
#: cross-case memory exists yet (ADR-0013's explicit scope cut: no
#: cross-case correlation). A future Memory Agent supplies a real value
#: through the same `ConfidenceEngine.calculate(..., historical_evidence=...)`
#: parameter without any signature change.
DEFAULT_HISTORICAL_EVIDENCE = 0.5


class FindingConfidenceWeights(BaseModel):
    """Configurable weighting for each of the seven dimensions. Must sum to
    1.0 — validated so a misconfigured `.env` fails fast at construction
    time, not silently mis-scores every Finding."""

    model_config = ConfigDict(frozen=True)

    ioc_quality: float = Field(default=1 / 7, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=1 / 7, ge=0.0, le=1.0)
    supporting_indicator_score: float = Field(default=1 / 7, ge=0.0, le=1.0)
    rule_strength: float = Field(default=1 / 7, ge=0.0, le=1.0)
    mapping_quality: float = Field(default=1 / 7, ge=0.0, le=1.0)
    source_reliability: float = Field(default=1 / 7, ge=0.0, le=1.0)
    historical_evidence: float = Field(default=1 / 7, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> FindingConfidenceWeights:
        total = (
            self.ioc_quality
            + self.evidence_quality
            + self.supporting_indicator_score
            + self.rule_strength
            + self.mapping_quality
            + self.source_reliability
            + self.historical_evidence
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"FindingConfidenceWeights must sum to 1.0, got {total!r}.")
        return self


class ConfidenceEngine:
    """Computes the composite `FindingConfidence` for one candidate Finding
    from its supporting `ScoredIOC`s and `MitreMapping`s."""

    def __init__(self, *, weights: FindingConfidenceWeights | None = None) -> None:
        self._weights = weights or FindingConfidenceWeights()

    def calculate(
        self,
        iocs: list[ScoredIOC],
        mappings: list[MitreMapping],
        *,
        source_reliability: SourceReliability = SourceReliability.UNKNOWN,
        historical_evidence: float = DEFAULT_HISTORICAL_EVIDENCE,
    ) -> FindingConfidence:
        if not iocs:
            raise ValueError("ConfidenceEngine.calculate requires at least one ScoredIOC.")

        ioc_quality = sum(ioc.record.confidence for ioc in iocs) / len(iocs)
        evidence_quality = sum(ioc.score.evidence_quality for ioc in iocs) / len(iocs)
        supporting_indicator_score = min(len(iocs) / SUPPORTING_INDICATOR_SATURATION_COUNT, 1.0)
        rule_strength = (
            sum(mapping.factors.rule_strength for mapping in mappings) / len(mappings)
            if mappings
            else 0.0
        )
        mapping_quality = (
            sum(mapping.confidence for mapping in mappings) / len(mappings) if mappings else 0.0
        )
        source_reliability_weight = _SOURCE_RELIABILITY_WEIGHTS[source_reliability]
        historical_evidence_clamped = max(0.0, min(1.0, historical_evidence))

        composite = (
            self._weights.ioc_quality * ioc_quality
            + self._weights.evidence_quality * evidence_quality
            + self._weights.supporting_indicator_score * supporting_indicator_score
            + self._weights.rule_strength * rule_strength
            + self._weights.mapping_quality * mapping_quality
            + self._weights.source_reliability * source_reliability_weight
            + self._weights.historical_evidence * historical_evidence_clamped
        )

        return FindingConfidence(
            ioc_quality=ioc_quality,
            evidence_quality=evidence_quality,
            supporting_indicator_score=supporting_indicator_score,
            rule_strength=rule_strength,
            mapping_quality=mapping_quality,
            source_reliability=source_reliability_weight,
            historical_evidence=historical_evidence_clamped,
            composite=max(0.0, min(1.0, composite)),
        )
