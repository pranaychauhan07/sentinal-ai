"""Vulnerability Scoring Engine — deterministic, pure functions per
constitution §1.9. Weights are configurable (task requirement: "do not
hardcode scoring values"), defaulting to an even split, overridable via
`VulnerabilityScoringWeights`. Mirrors
`core.threat_intel.scoring.ThreatScoringEngine`'s shape exactly, with the
task's six named dimensions for this framework: CVSS score, severity,
confidence, asset criticality, source reliability, evidence quality.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.vulnerabilities.models import (
    AssetCriticality,
    DetectionSource,
    SourceReliability,
    VulnerabilityRecord,
    VulnerabilityScore,
    VulnerabilitySeverity,
)

#: `VulnerabilitySeverity` -> a 0.0-1.0 weight. A small, intentional
#: duplication of `core.vulnerabilities.severity.SEVERITY_ORDER`'s scale as
#: a weight table, not an import across sibling modules — matching
#: `core.findings.confidence_engine`'s documented precedent of duplicating a
#: small constant rather than reaching past a leaf-sibling's private API.
_SEVERITY_WEIGHTS: dict[VulnerabilitySeverity, float] = {
    VulnerabilitySeverity.INFO: 0.0,
    VulnerabilitySeverity.LOW: 0.25,
    VulnerabilitySeverity.MEDIUM: 0.5,
    VulnerabilitySeverity.HIGH: 0.75,
    VulnerabilitySeverity.CRITICAL: 1.0,
}

#: Duplicated from `core.vulnerabilities.confidence_engine`'s identical
#: table for the same "no cross-sibling private import" reason above.
_SOURCE_RELIABILITY_WEIGHTS: dict[SourceReliability, float] = {
    SourceReliability.UNKNOWN: 0.2,
    SourceReliability.LOW: 0.4,
    SourceReliability.MEDIUM: 0.6,
    SourceReliability.HIGH: 0.8,
    SourceReliability.CONFIRMED: 1.0,
}

#: `AssetCriticality` -> a 0.0-1.0 weight (task requirement: "Asset
#: Criticality"). No per-case asset inventory exists in this framework
#: (documented limitation) — callers pass `AssetCriticality.MEDIUM` by
#: default unless a future asset-inventory feature supplies a real value.
_ASSET_CRITICALITY_WEIGHTS: dict[AssetCriticality, float] = {
    AssetCriticality.LOW: 0.25,
    AssetCriticality.MEDIUM: 0.5,
    AssetCriticality.HIGH: 0.75,
    AssetCriticality.CRITICAL: 1.0,
}

#: `DetectionSource` -> `SourceReliability`, mirroring
#: `core.vulnerabilities.confidence_engine`'s identical mapping (kept as its
#: own small constant here rather than importing that module's private
#: mapping, matching `core.findings.confidence_engine`'s documented
#: precedent of duplicating a small constant rather than reaching past a
#: leaf-sibling's private API).
_DETECTION_SOURCE_RELIABILITY: dict[DetectionSource, SourceReliability] = {
    DetectionSource.NESSUS: SourceReliability.HIGH,
    DetectionSource.OPENVAS: SourceReliability.HIGH,
}


class VulnerabilityScoringWeights(BaseModel):
    """Configurable weighting for each of the six scoring dimensions the
    task requires. Must sum to 1.0 — validated so a misconfigured `.env`
    fails fast at construction time, not silently mis-scores every
    vulnerability."""

    model_config = ConfigDict(frozen=True)

    cvss: float = Field(default=1 / 6, ge=0.0, le=1.0)
    severity: float = Field(default=1 / 6, ge=0.0, le=1.0)
    confidence: float = Field(default=1 / 6, ge=0.0, le=1.0)
    asset_criticality: float = Field(default=1 / 6, ge=0.0, le=1.0)
    source_reliability: float = Field(default=1 / 6, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=1 / 6, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> VulnerabilityScoringWeights:
        total = (
            self.cvss
            + self.severity
            + self.confidence
            + self.asset_criticality
            + self.source_reliability
            + self.evidence_quality
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"VulnerabilityScoringWeights must sum to 1.0, got {total!r}.")
        return self


class VulnerabilityThreatScoringEngine:
    """Computes the composite `VulnerabilityScore` for one
    `VulnerabilityRecord`."""

    def __init__(self, *, weights: VulnerabilityScoringWeights | None = None) -> None:
        self._weights = weights or VulnerabilityScoringWeights()

    def score(
        self,
        record: VulnerabilityRecord,
        *,
        confidence: float,
        evidence_quality: float,
        asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
    ) -> VulnerabilityScore:
        best_cvss = record.best_cvss
        cvss_component = (
            best_cvss.base_score / 10.0
            if best_cvss is not None and best_cvss.base_score is not None
            else 0.0
        )
        severity_weight = _SEVERITY_WEIGHTS[record.severity]
        asset_criticality_weight = _ASSET_CRITICALITY_WEIGHTS[asset_criticality]
        reliability = _DETECTION_SOURCE_RELIABILITY.get(
            record.detection_source, SourceReliability.UNKNOWN
        )
        source_reliability_weight = _SOURCE_RELIABILITY_WEIGHTS[reliability]
        confidence_clamped = max(0.0, min(1.0, confidence))
        evidence_quality_clamped = max(0.0, min(1.0, evidence_quality))

        composite_fraction = (
            self._weights.cvss * cvss_component
            + self._weights.severity * severity_weight
            + self._weights.confidence * confidence_clamped
            + self._weights.asset_criticality * asset_criticality_weight
            + self._weights.source_reliability * source_reliability_weight
            + self._weights.evidence_quality * evidence_quality_clamped
        )

        return VulnerabilityScore(
            cvss_component=cvss_component,
            severity_weight=severity_weight,
            confidence=confidence_clamped,
            asset_criticality=asset_criticality_weight,
            source_reliability=source_reliability_weight,
            evidence_quality=evidence_quality_clamped,
            composite_score=round(max(0.0, min(100.0, composite_fraction * 100.0)), 2),
        )
