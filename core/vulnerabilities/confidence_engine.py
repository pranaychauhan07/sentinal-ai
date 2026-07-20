"""`VulnerabilityConfidenceEngine` — deterministic, configurable combination
of four confidence dimensions (constitution §1.9: "one correct, checkable
answer" work, never an LLM guess). Weights are configurable (task
requirement: "do not hardcode scoring values"), mirroring
`core.findings.confidence_engine.FindingConfidenceWeights`'s "must sum to
1.0" pattern exactly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.vulnerabilities.models import DetectionSource, SourceReliability, VulnerabilityRecord

#: `DetectionSource` -> a 0.0-1.0 reliability weight (task requirement:
#: "Source Reliability"). Both scanners are well-established, actively
#: maintained tools; the small gap reflects Nessus's larger, more
#: frequently-updated plugin feed, not a judgment about OpenVAS's quality.
_DETECTION_SOURCE_RELIABILITY: dict[DetectionSource, SourceReliability] = {
    DetectionSource.NESSUS: SourceReliability.HIGH,
    DetectionSource.OPENVAS: SourceReliability.HIGH,
}
_SOURCE_RELIABILITY_WEIGHTS: dict[SourceReliability, float] = {
    SourceReliability.UNKNOWN: 0.2,
    SourceReliability.LOW: 0.4,
    SourceReliability.MEDIUM: 0.6,
    SourceReliability.HIGH: 0.8,
    SourceReliability.CONFIRMED: 1.0,
}


class VulnerabilityConfidenceWeights(BaseModel):
    """Configurable weighting for each of the four dimensions. Must sum to
    1.0 — validated so a misconfigured `.env` fails fast at construction
    time, not silently mis-scores every vulnerability."""

    model_config = ConfigDict(frozen=True)

    source_reliability: float = Field(default=0.25, ge=0.0, le=1.0)
    cvss_presence: float = Field(default=0.25, ge=0.0, le=1.0)
    plugin_metadata_completeness: float = Field(default=0.25, ge=0.0, le=1.0)
    host_identification: float = Field(default=0.25, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> VulnerabilityConfidenceWeights:
        total = (
            self.source_reliability
            + self.cvss_presence
            + self.plugin_metadata_completeness
            + self.host_identification
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"VulnerabilityConfidenceWeights must sum to 1.0, got {total!r}.")
        return self


class VulnerabilityConfidenceEngine:
    """Computes a 0.0-1.0 confidence value for one `VulnerabilityRecord`."""

    def __init__(self, *, weights: VulnerabilityConfidenceWeights | None = None) -> None:
        self._weights = weights or VulnerabilityConfidenceWeights()

    def calculate(self, record: VulnerabilityRecord) -> float:
        reliability = _DETECTION_SOURCE_RELIABILITY.get(
            record.detection_source, SourceReliability.UNKNOWN
        )
        source_reliability_score = _SOURCE_RELIABILITY_WEIGHTS[reliability]
        cvss_presence_score = 1.0 if record.best_cvss is not None else 0.3
        plugin_metadata_completeness_score = (
            sum(
                (
                    bool(record.plugin_id),
                    bool(record.plugin_name),
                    bool(record.description),
                    bool(record.references),
                )
            )
            / 4.0
        )
        host_identification_score = sum((bool(record.host), bool(record.ip_address))) / 2.0

        composite = (
            self._weights.source_reliability * source_reliability_score
            + self._weights.cvss_presence * cvss_presence_score
            + self._weights.plugin_metadata_completeness * plugin_metadata_completeness_score
            + self._weights.host_identification * host_identification_score
        )
        return round(max(0.0, min(1.0, composite)), 4)
