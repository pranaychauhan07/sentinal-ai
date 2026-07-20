"""Linux Threat Scoring Engine — deterministic, pure functions per
constitution §1.9. The task names exactly seven dimensions: detection
confidence, event frequency, severity, evidence quality, source reliability,
IOC correlation, existing findings. Weights are configurable (task
requirement: "do not hardcode scoring values"), mirroring
`core.vulnerabilities.scoring.VulnerabilityThreatScoringEngine`'s shape.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.linux_security.confidence_engine import LinuxSecurityConfidenceEngine
from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityScore,
    LinuxSecuritySeverity,
    ScoredLinuxSecurityCandidate,
    SourceReliability,
)

#: `LinuxSecuritySeverity` -> a 0.0-1.0 weight. A small, intentional
#: duplication of the five-level severity scale as a weight table (never a
#: cross-sibling-leaf import), matching
#: `core.vulnerabilities.scoring`'s identical, documented precedent.
_SEVERITY_WEIGHTS: dict[LinuxSecuritySeverity, float] = {
    LinuxSecuritySeverity.INFO: 0.0,
    LinuxSecuritySeverity.LOW: 0.25,
    LinuxSecuritySeverity.MEDIUM: 0.5,
    LinuxSecuritySeverity.HIGH: 0.75,
    LinuxSecuritySeverity.CRITICAL: 1.0,
}

_SOURCE_RELIABILITY_WEIGHTS: dict[SourceReliability, float] = {
    SourceReliability.UNKNOWN: 0.2,
    SourceReliability.LOW: 0.4,
    SourceReliability.MEDIUM: 0.6,
    SourceReliability.HIGH: 0.8,
    SourceReliability.CONFIRMED: 1.0,
}

#: Deterministic-parser-backed evidence (SSH auth log lines, syslog lines)
#: is treated as high reliability by default — this framework runs no live
#: enrichment lookups that could raise/lower it further (documented gap,
#: `core.linux_security.registry`'s unimplemented provider seam).
DEFAULT_SOURCE_RELIABILITY = SourceReliability.HIGH


class LinuxSecurityScoringWeights(BaseModel):
    """Configurable weighting for each of the seven scoring dimensions the
    task requires. Must sum to 1.0 — validated so a misconfigured `.env`
    fails fast at construction time."""

    model_config = ConfigDict(frozen=True)

    detection_confidence: float = Field(default=1 / 7, ge=0.0, le=1.0)
    event_frequency: float = Field(default=1 / 7, ge=0.0, le=1.0)
    severity: float = Field(default=1 / 7, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=1 / 7, ge=0.0, le=1.0)
    source_reliability: float = Field(default=1 / 7, ge=0.0, le=1.0)
    ioc_correlation: float = Field(default=1 / 7, ge=0.0, le=1.0)
    existing_findings: float = Field(default=1 / 7, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> LinuxSecurityScoringWeights:
        total = (
            self.detection_confidence
            + self.event_frequency
            + self.severity
            + self.evidence_quality
            + self.source_reliability
            + self.ioc_correlation
            + self.existing_findings
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"LinuxSecurityScoringWeights must sum to 1.0, got {total!r}.")
        return self


class LinuxThreatScoringEngine:
    """Computes the composite `LinuxSecurityScore` for one
    `LinuxSecurityCandidate`."""

    def __init__(self, *, weights: LinuxSecurityScoringWeights | None = None) -> None:
        self._weights = weights or LinuxSecurityScoringWeights()

    def score(
        self,
        candidate: LinuxSecurityCandidate,
        *,
        detection_confidence: float,
        evidence_quality: float,
        ioc_correlation: float = 0.0,
        existing_findings_count: int = 0,
        source_reliability: SourceReliability = DEFAULT_SOURCE_RELIABILITY,
    ) -> LinuxSecurityScore:
        event_frequency_score = min(1.0, candidate.occurrence_count / 10.0)
        severity_weight = _SEVERITY_WEIGHTS[candidate.severity]
        source_reliability_weight = _SOURCE_RELIABILITY_WEIGHTS[source_reliability]
        detection_confidence_clamped = max(0.0, min(1.0, detection_confidence))
        evidence_quality_clamped = max(0.0, min(1.0, evidence_quality))
        ioc_correlation_clamped = max(0.0, min(1.0, ioc_correlation))
        existing_findings_score = min(1.0, existing_findings_count / 5.0)

        composite_fraction = (
            self._weights.detection_confidence * detection_confidence_clamped
            + self._weights.event_frequency * event_frequency_score
            + self._weights.severity * severity_weight
            + self._weights.evidence_quality * evidence_quality_clamped
            + self._weights.source_reliability * source_reliability_weight
            + self._weights.ioc_correlation * ioc_correlation_clamped
            + self._weights.existing_findings * existing_findings_score
        )

        return LinuxSecurityScore(
            detection_confidence=detection_confidence_clamped,
            event_frequency=event_frequency_score,
            severity_weight=severity_weight,
            evidence_quality=evidence_quality_clamped,
            source_reliability=source_reliability_weight,
            ioc_correlation=ioc_correlation_clamped,
            existing_findings=existing_findings_score,
            composite_score=round(max(0.0, min(100.0, composite_fraction * 100.0)), 2),
        )


def score_candidates(
    candidates: list[LinuxSecurityCandidate],
    *,
    evidence_quality: float,
    confidence_engine: LinuxSecurityConfidenceEngine,
    scoring_engine: LinuxThreatScoringEngine,
) -> list[ScoredLinuxSecurityCandidate]:
    """Shared confidence + scoring pass over a full candidate set — the one
    place corroboration counting (how many other candidates share the same
    `(category, subject)` key) lives, so `core.linux_security.extractor` and
    `core.services.linux_security_service` never duplicate this logic
    (constitution §2, "never duplicated across files")."""
    subject_counts: dict[tuple[str, str], int] = {}
    for candidate in candidates:
        key = (candidate.category.value, candidate.subject)
        subject_counts[key] = subject_counts.get(key, 0) + 1

    scored: list[ScoredLinuxSecurityCandidate] = []
    for candidate in candidates:
        key = (candidate.category.value, candidate.subject)
        corroborating = subject_counts.get(key, 1) - 1
        confidence = confidence_engine.calculate(candidate, corroborating_count=corroborating)
        score = scoring_engine.score(
            candidate,
            detection_confidence=confidence,
            evidence_quality=evidence_quality,
            existing_findings_count=corroborating,
        )
        scored.append(
            ScoredLinuxSecurityCandidate(
                candidate=candidate.model_copy(update={"confidence": confidence}),
                score=score,
                occurrence_count=candidate.occurrence_count,
            )
        )
    return scored
