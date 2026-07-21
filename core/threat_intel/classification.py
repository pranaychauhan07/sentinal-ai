"""Threat Classification Engine — maps a `ThreatScore` + its rule matches to
an `IOCClassification` category. Deliberately not a MITRE technique mapper
(docs/adr/0012 scope cut: no MITRE mapping in this framework).

Thresholds are configurable (`Settings.threat_intel_malicious_score_threshold`
/ `threat_intel_suspicious_score_threshold`), never hardcoded magic numbers
duplicated across call sites (constitution §2, "Constants").
"""

from __future__ import annotations

from core.threat_intel.models import (
    IOCClassification,
    RuleMatchResult,
    ThreatCategory,
    ThreatScore,
    ThreatSeverity,
)

DEFAULT_MALICIOUS_THRESHOLD = 70.0
DEFAULT_SUSPICIOUS_THRESHOLD = 40.0

#: `composite_score` at or above which a `MALICIOUS`-classified IOC is
#: assessed `CRITICAL` rather than `HIGH` — a second, finer threshold inside
#: the "malicious" band, mirroring `DEFAULT_MALICIOUS_THRESHOLD`'s own
#: "configurable, not a magic number duplicated across call sites" shape
#: (constitution §2).
DEFAULT_CRITICAL_SEVERITY_THRESHOLD = 90.0

#: `composite_score` at or above which a `SUSPICIOUS`-classified IOC is
#: assessed `MEDIUM` rather than `LOW`.
DEFAULT_SUSPICIOUS_MEDIUM_THRESHOLD = 55.0


def derive_severity_from_classification(
    classification: IOCClassification,
    score: ThreatScore,
    *,
    critical_threshold: float = DEFAULT_CRITICAL_SEVERITY_THRESHOLD,
    suspicious_medium_threshold: float = DEFAULT_SUSPICIOUS_MEDIUM_THRESHOLD,
) -> ThreatSeverity:
    """Derives an `IOCRecord.severity` value from the same
    `IOCClassification`/`ThreatScore` this engine already computed —
    closing a real gap where `IOCRecord.severity` previously stayed at its
    Pydantic default (`ThreatSeverity.INFO`) for every IOC regardless of how
    it classified, because nothing in the pipeline ever derived a real value
    from the classification. That silently disconnected `core.findings.
    severity.assign_severity` (which reads `ioc.record.severity` as its
    base) from the actual threat signal already computed here — the root
    cause of a Finding scoring "low" severity for IOCs a human analyst
    would immediately call critical. Deterministic, pure (constitution
    §1.9): the same `(classification, score)` pair always derives the same
    severity."""
    if classification.category is ThreatCategory.MALICIOUS:
        return (
            ThreatSeverity.CRITICAL
            if score.composite_score >= critical_threshold
            else ThreatSeverity.HIGH
        )
    if classification.category is ThreatCategory.SUSPICIOUS:
        return (
            ThreatSeverity.MEDIUM
            if score.composite_score >= suspicious_medium_threshold
            else ThreatSeverity.LOW
        )
    return ThreatSeverity.INFO


class ThreatClassificationEngine:
    """Deterministic score-threshold classifier. A rule match always at
    least elevates an IOC to `SUSPICIOUS`, even if its composite score
    happens to fall below the suspicious threshold — a matched detection
    rule is stronger, more specific evidence than an unadorned score."""

    def __init__(
        self,
        *,
        malicious_threshold: float = DEFAULT_MALICIOUS_THRESHOLD,
        suspicious_threshold: float = DEFAULT_SUSPICIOUS_THRESHOLD,
    ) -> None:
        if not (0.0 <= suspicious_threshold <= malicious_threshold <= 100.0):
            raise ValueError(
                "Thresholds must satisfy 0 <= suspicious_threshold <= malicious_threshold <= 100."
            )
        self._malicious_threshold = malicious_threshold
        self._suspicious_threshold = suspicious_threshold

    def classify(
        self, score: ThreatScore, rule_matches: list[RuleMatchResult]
    ) -> IOCClassification:
        matched_rule_ids = tuple(match.rule_id for match in rule_matches if match.matched)

        if score.composite_score >= self._malicious_threshold:
            return IOCClassification(
                category=ThreatCategory.MALICIOUS,
                reason=(
                    f"composite score {score.composite_score} >= "
                    f"malicious threshold {self._malicious_threshold}"
                ),
                matched_rule_ids=matched_rule_ids,
            )

        if score.composite_score >= self._suspicious_threshold or matched_rule_ids:
            reason = (
                f"composite score {score.composite_score} >= "
                f"suspicious threshold {self._suspicious_threshold}"
                if score.composite_score >= self._suspicious_threshold
                else f"{len(matched_rule_ids)} detection rule(s) matched"
            )
            return IOCClassification(
                category=ThreatCategory.SUSPICIOUS,
                reason=reason,
                matched_rule_ids=matched_rule_ids,
            )

        if score.confidence <= 0.0:
            return IOCClassification(
                category=ThreatCategory.UNKNOWN,
                reason="zero confidence — insufficient evidence to classify",
                matched_rule_ids=matched_rule_ids,
            )

        return IOCClassification(
            category=ThreatCategory.BENIGN,
            reason=(
                f"composite score {score.composite_score} below "
                f"suspicious threshold {self._suspicious_threshold} and no rules matched"
            ),
            matched_rule_ids=matched_rule_ids,
        )
