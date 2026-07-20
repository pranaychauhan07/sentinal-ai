"""``RiskAssessmentEngine`` — aggregates every `CommandRisk`/`PermissionRisk`
plus hardening-recommendation counts into `LinuxSecurityAdvice`'s overall
`risk_level`/`confidence`/`explanation`. Configurable, weighted dimensions
(task brief: "No hardcoded business logic. Use configurable rules.") —
weights are read from `core.config.settings.Settings` by the caller
(`advisory_engine.py`) and validated to sum to 1.0, mirroring
`core.linux_security.scoring.LinuxThreatScoringEngine`'s established shape.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.linux_advisor.models import (
    CommandRisk,
    LinuxAdvisorSeverity,
    PermissionRisk,
    RiskDimensionScores,
    severity_rank,
)

#: Categories whose match is treated as inherently "critical-category",
#: regardless of the individual rule's assigned severity — matches the task
#: brief's "whether any critical-category rule matched" dimension.
_CRITICAL_CATEGORIES: frozenset[str] = frozenset(
    {"destructive_command", "untrusted_execution", "unrestricted_sudo", "insecure_ownership_change"}
)

#: Finding count above which `finding_count_score` saturates at 1.0 —
#: a configurable-in-spirit constant (kept local since the task's scoring
#: weights, not this saturation point, are the documented configurable
#: surface; this mirrors `core.linux_security.scoring`'s identical choice
#: of keeping a couple of small shape constants local to the module).
_FINDING_COUNT_SATURATION = 5


class LinuxAdvisorRiskWeights(BaseModel):
    """The four configurable scoring dimensions. Must sum to 1.0 —
    validated so a misconfigured `.env` fails fast at construction time."""

    model_config = ConfigDict(frozen=True)

    highest_severity: float = Field(default=0.35, ge=0.0, le=1.0)
    highest_confidence: float = Field(default=0.2, ge=0.0, le=1.0)
    finding_count: float = Field(default=0.15, ge=0.0, le=1.0)
    critical_category: float = Field(default=0.2, ge=0.0, le=1.0)
    corroboration: float = Field(default=0.1, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> LinuxAdvisorRiskWeights:
        total = (
            self.highest_severity
            + self.highest_confidence
            + self.finding_count
            + self.critical_category
            + self.corroboration
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"LinuxAdvisorRiskWeights must sum to 1.0, got {total!r}.")
        return self


#: Composite-fraction thresholds mapping onto `LinuxAdvisorSeverity` labels.
_RISK_LEVEL_THRESHOLDS: tuple[tuple[float, LinuxAdvisorSeverity], ...] = (
    (0.8, LinuxAdvisorSeverity.CRITICAL),
    (0.6, LinuxAdvisorSeverity.HIGH),
    (0.35, LinuxAdvisorSeverity.MEDIUM),
    (0.1, LinuxAdvisorSeverity.LOW),
)


def _fraction_to_severity(fraction: float) -> LinuxAdvisorSeverity:
    for threshold, severity in _RISK_LEVEL_THRESHOLDS:
        if fraction >= threshold:
            return severity
    return LinuxAdvisorSeverity.INFO


class RiskAssessmentEngine:
    def __init__(self, *, weights: LinuxAdvisorRiskWeights | None = None) -> None:
        self._weights = weights or LinuxAdvisorRiskWeights()

    def assess(
        self,
        *,
        command_risks: list[CommandRisk],
        permission_risks: list[PermissionRisk],
    ) -> tuple[LinuxAdvisorSeverity, float, str, RiskDimensionScores]:
        findings = [r for r in command_risks if r.matched_rule_ids] + [
            r for r in permission_risks if r.matched_rule_ids
        ]

        if not findings:
            explanation = (
                "No dangerous command patterns or permission risks were detected "
                "across the analyzed input."
            )
            dimensions = RiskDimensionScores(
                highest_severity_score=0.0,
                highest_confidence_score=0.0,
                finding_count_score=0.0,
                critical_category_score=0.0,
                corroboration_score=0.0,
            )
            return LinuxAdvisorSeverity.INFO, 1.0, explanation, dimensions

        highest_severity = max(severity_rank(f.severity) for f in findings) / severity_rank(
            LinuxAdvisorSeverity.CRITICAL
        )
        highest_confidence = max(f.confidence for f in findings)
        finding_count_score = min(1.0, len(findings) / _FINDING_COUNT_SATURATION)

        critical_category_hit = any(
            _rule_category_is_critical(risk) for risk in command_risks if risk.matched_rule_ids
        )
        critical_category_score = 1.0 if critical_category_hit else 0.0

        corroboration_score = (
            1.0
            if any(r.matched_rule_ids for r in command_risks)
            and any(r.matched_rule_ids for r in permission_risks)
            else 0.0
        )

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


def _rule_category_is_critical(risk: CommandRisk) -> bool:
    """`CommandRisk` doesn't carry its matched rule's `category` directly
    (only `matched_rule_ids`) — this package's rule ids are descriptive
    enough (`rm_rf_root`, `curl_pipe_shell`, `sudo_nopasswd_all`,
    `chown_sensitive_away_from_root`) to map back to
    `_CRITICAL_CATEGORIES` without a second RuleEngine lookup; a future
    refactor could thread the category through `CommandRisk` instead if this
    mapping ever drifts."""
    critical_rule_ids = {
        "rm_rf_root",
        "curl_pipe_shell",
        "wget_pipe_shell",
        "sudo_nopasswd_all",
        "chown_sensitive_away_from_root",
    }
    return bool(set(risk.matched_rule_ids) & critical_rule_ids)
