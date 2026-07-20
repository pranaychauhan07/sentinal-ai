"""`LinuxSecurityConfidenceEngine` — deterministic, configurable combination
of confidence dimensions (constitution §1.9: "one correct, checkable answer"
work, never an LLM guess). Weights are configurable (task requirement: "do
not hardcode scoring values"), mirroring
`core.vulnerabilities.confidence_engine.VulnerabilityConfidenceWeights`'s
"must sum to 1.0" pattern exactly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.linux_security.models import LinuxSecurityCandidate


class LinuxSecurityConfidenceWeights(BaseModel):
    """Configurable weighting for each dimension. Must sum to 1.0 —
    validated so a misconfigured `.env` fails fast at construction time."""

    model_config = ConfigDict(frozen=True)

    pattern_match_strength: float = Field(default=0.3, ge=0.0, le=1.0)
    occurrence_signal: float = Field(default=0.25, ge=0.0, le=1.0)
    evidence_completeness: float = Field(default=0.25, ge=0.0, le=1.0)
    corroboration: float = Field(default=0.2, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> LinuxSecurityConfidenceWeights:
        total = (
            self.pattern_match_strength
            + self.occurrence_signal
            + self.evidence_completeness
            + self.corroboration
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"LinuxSecurityConfidenceWeights must sum to 1.0, got {total!r}.")
        return self


class LinuxSecurityConfidenceEngine:
    """Computes a 0.0-1.0 confidence value for one `LinuxSecurityCandidate`,
    optionally aware of how many *other* candidates corroborate it (e.g. a
    brute-force candidate corroborated by a compromise-after-brute-force
    candidate for the same subject is more confidently a real incident)."""

    def __init__(self, *, weights: LinuxSecurityConfidenceWeights | None = None) -> None:
        self._weights = weights or LinuxSecurityConfidenceWeights()

    def calculate(
        self, candidate: LinuxSecurityCandidate, *, corroborating_count: int = 0
    ) -> float:
        pattern_match_strength_score = candidate.confidence
        occurrence_signal_score = min(1.0, candidate.occurrence_count / 5.0)
        evidence_completeness_score = (
            sum(
                (
                    bool(candidate.evidence_id),
                    bool(candidate.line_numbers),
                    bool(candidate.description),
                )
            )
            / 3.0
        )
        corroboration_score = min(1.0, corroborating_count / 2.0)

        composite = (
            self._weights.pattern_match_strength * pattern_match_strength_score
            + self._weights.occurrence_signal * occurrence_signal_score
            + self._weights.evidence_completeness * evidence_completeness_score
            + self._weights.corroboration * corroboration_score
        )
        return round(max(0.0, min(1.0, composite)), 4)
