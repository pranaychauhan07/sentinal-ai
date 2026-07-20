"""``RiskAssessmentEngine`` — aggregates every generated `OwaspFinding` into
`WebSecurityAdvice`'s overall `risk_level`/`confidence`/`explanation`.
Configurable, weighted dimensions — weights are read from
`core.config.settings.Settings` by the caller (`advisory_engine.py`) and
validated to sum to 1.0, mirroring
`core.linux_advisor.risk_assessment.RiskAssessmentEngine`'s established
shape (each leaf owns its own copy; no cross-leaf import).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.owasp_web.models import (
    OwaspCategory,
    OwaspFinding,
    RiskDimensionScores,
    WebSecuritySeverity,
    severity_rank,
)

#: Categories whose match is treated as inherently "critical-category",
#: regardless of the individual finding's assigned severity.
_CRITICAL_CATEGORIES: frozenset[OwaspCategory] = frozenset(
    {
        OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        OwaspCategory.A07_AUTHENTICATION_FAILURES,
        OwaspCategory.A08_SOFTWARE_DATA_INTEGRITY_FAILURES,
    }
)

#: Finding count above which `finding_count_score` saturates at 1.0.
_FINDING_COUNT_SATURATION = 5


class WebSecurityRiskWeights(BaseModel):
    """The five configurable scoring dimensions. Must sum to 1.0 — validated
    so a misconfigured `.env` fails fast at construction time."""

    model_config = ConfigDict(frozen=True)

    highest_severity: float = Field(default=0.35, ge=0.0, le=1.0)
    highest_confidence: float = Field(default=0.2, ge=0.0, le=1.0)
    finding_count: float = Field(default=0.15, ge=0.0, le=1.0)
    critical_category: float = Field(default=0.2, ge=0.0, le=1.0)
    corroboration: float = Field(default=0.1, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> WebSecurityRiskWeights:
        total = (
            self.highest_severity
            + self.highest_confidence
            + self.finding_count
            + self.critical_category
            + self.corroboration
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"WebSecurityRiskWeights must sum to 1.0, got {total!r}.")
        return self


#: Composite-fraction thresholds mapping onto `WebSecuritySeverity` labels.
_RISK_LEVEL_THRESHOLDS: tuple[tuple[float, WebSecuritySeverity], ...] = (
    (0.8, WebSecuritySeverity.CRITICAL),
    (0.6, WebSecuritySeverity.HIGH),
    (0.35, WebSecuritySeverity.MEDIUM),
    (0.1, WebSecuritySeverity.LOW),
)


def _fraction_to_severity(fraction: float) -> WebSecuritySeverity:
    for threshold, severity in _RISK_LEVEL_THRESHOLDS:
        if fraction >= threshold:
            return severity
    return WebSecuritySeverity.INFO


class RiskAssessmentEngine:
    def __init__(self, *, weights: WebSecurityRiskWeights | None = None) -> None:
        self._weights = weights or WebSecurityRiskWeights()

    def assess(
        self, *, findings: list[OwaspFinding], distinct_sources: set[str]
    ) -> tuple[WebSecuritySeverity, float, str, RiskDimensionScores]:
        if not findings:
            explanation = "No OWASP-mapped issues were detected across the analyzed HTTP traffic."
            dimensions = RiskDimensionScores(
                highest_severity_score=0.0,
                highest_confidence_score=0.0,
                finding_count_score=0.0,
                critical_category_score=0.0,
                corroboration_score=0.0,
            )
            return WebSecuritySeverity.INFO, 1.0, explanation, dimensions

        highest_severity = max(severity_rank(f.severity) for f in findings) / severity_rank(
            WebSecuritySeverity.CRITICAL
        )
        highest_confidence = max(f.confidence for f in findings)
        finding_count_score = min(1.0, len(findings) / _FINDING_COUNT_SATURATION)

        critical_category_hit = any(f.category in _CRITICAL_CATEGORIES for f in findings)
        critical_category_score = 1.0 if critical_category_hit else 0.0

        corroboration_score = 1.0 if len(distinct_sources) > 1 else 0.0

        dimensions = RiskDimensionScores(
            highest_severity_score=highest_severity,
            highest_confidence_score=highest_confidence,
            finding_count_score=finding_count_score,
            critical_category_score=critical_category_score,
            corroboration_score=corroboration_score,
        )

        composite = (
            self._weights.highest_severity * highest_severity
            + self._weights.highest_confidence * highest_confidence
            + self._weights.finding_count * finding_count_score
            + self._weights.critical_category * critical_category_score
            + self._weights.corroboration * corroboration_score
        )

        overall_risk_level = _fraction_to_severity(composite)
        explanation = (
            f"{len(findings)} finding(s) detected; highest individual severity "
            f"'{max(findings, key=lambda f: severity_rank(f.severity)).severity.value}'; "
            f"composite risk score {composite:.2f} -> '{overall_risk_level.value}'."
        )
        return overall_risk_level, round(highest_confidence, 2), explanation, dimensions
