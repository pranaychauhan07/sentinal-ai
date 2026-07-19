"""Threat Classification Engine — maps a `ThreatScore` + its rule matches to
an `IOCClassification` category. Deliberately not a MITRE technique mapper
(docs/adr/0012 scope cut: no MITRE mapping in this framework).

Thresholds are configurable (`Settings.threat_intel_malicious_score_threshold`
/ `threat_intel_suspicious_score_threshold`), never hardcoded magic numbers
duplicated across call sites (constitution §2, "Constants").
"""

from __future__ import annotations

from core.threat_intel.models import IOCClassification, RuleMatchResult, ThreatCategory, ThreatScore

DEFAULT_MALICIOUS_THRESHOLD = 70.0
DEFAULT_SUSPICIOUS_THRESHOLD = 40.0


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
