"""`DetectionRuleEngine` — the Detection Rule Engine (task requirement:
pattern/regex/threshold/composable rules, rule metadata/versioning/priority/
enable-disable, future Sigma compatibility per `core.threat_intel.models.
DetectionRule`'s Sigma-adjacent field naming).
"""

from __future__ import annotations

import re

from core.logging import get_logger
from core.threat_intel.exceptions import UnsafeRegexError
from core.threat_intel.models import (
    CompositeOperator,
    DetectionRule,
    IOCRecord,
    RuleMatchResult,
    ThresholdOperator,
)
from core.threat_intel.rule_validation import validate_regex_safety, validate_rule_shape

_logger = get_logger(__name__)

#: Regex input is always sliced to this length before matching — defense in
#: depth alongside `validate_regex_safety`'s static pattern checks
#: (constitution §10).
MAX_REGEX_MATCH_INPUT_CHARS = 2_000


class DetectionRuleEngine:
    """Holds a set of `DetectionRule`s and evaluates them against a
    candidate `IOCRecord` set. Every dependency (the rule set itself) is
    explicit constructor/method state — no module-level global registry
    (constitution §2)."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}
        self._compiled_regex: dict[str, re.Pattern[str]] = {}

    def register_rule(self, rule: DetectionRule) -> None:
        """Validate `rule`'s shape and (for REGEX rules) safety before
        accepting it — an invalid or unsafe rule is rejected at
        registration time, never discovered mid-evaluation."""
        validate_rule_shape(rule, known_rule_ids=frozenset(self._rules.keys()))
        if rule.rule_type.value == "regex" and rule.regex is not None:
            self._compiled_regex[rule.rule_id] = re.compile(rule.regex)
        self._rules[rule.rule_id] = rule

    def enable_rule(self, rule_id: str) -> None:
        self._set_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> None:
        self._set_enabled(rule_id, False)

    def _set_enabled(self, rule_id: str, enabled: bool) -> None:
        rule = self._rules.get(rule_id)
        if rule is not None:
            self._rules[rule_id] = rule.model_copy(update={"enabled": enabled})

    def list_rules(self) -> tuple[DetectionRule, ...]:
        return tuple(self._rules.values())

    def evaluate(self, iocs: list[IOCRecord]) -> list[RuleMatchResult]:
        """Evaluate every enabled rule, highest `priority` first. Simple
        rules (`PATTERN`/`REGEX`) run per-IOC; `THRESHOLD` runs once against
        the full candidate set; `COMPOSITE` runs last, combining the
        already-computed results of the rules it references."""
        enabled_rules = sorted(
            (r for r in self._rules.values() if r.enabled),
            key=lambda r: r.priority,
            reverse=True,
        )
        results: list[RuleMatchResult] = []
        matched_by_rule: dict[str, bool] = {}

        simple_rules = [r for r in enabled_rules if r.rule_type.value in ("pattern", "regex")]
        threshold_rules = [r for r in enabled_rules if r.rule_type.value == "threshold"]
        composite_rules = [r for r in enabled_rules if r.rule_type.value == "composite"]

        for rule in simple_rules:
            rule_matched = False
            for ioc in iocs:
                if rule.ioc_types and ioc.ioc_type not in rule.ioc_types:
                    continue
                match = self._evaluate_simple_rule(rule, ioc)
                if match is not None:
                    results.append(match)
                    rule_matched = True
            matched_by_rule[rule.rule_id] = rule_matched

        for rule in threshold_rules:
            match = self._evaluate_threshold_rule(rule, iocs)
            matched_by_rule[rule.rule_id] = match is not None
            if match is not None:
                results.append(match)

        for rule in composite_rules:
            match = self._evaluate_composite_rule(rule, matched_by_rule)
            matched_by_rule[rule.rule_id] = match is not None
            if match is not None:
                results.append(match)

        return results

    def _evaluate_simple_rule(self, rule: DetectionRule, ioc: IOCRecord) -> RuleMatchResult | None:
        if rule.rule_type.value == "pattern":
            return self._evaluate_pattern_rule(rule, ioc)
        return self._evaluate_regex_rule(rule, ioc)

    def _evaluate_pattern_rule(self, rule: DetectionRule, ioc: IOCRecord) -> RuleMatchResult | None:
        if rule.pattern is None:
            return None
        if rule.pattern.lower() not in ioc.value.lower():
            return None
        return RuleMatchResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            matched=True,
            ioc_id=ioc.ioc_id,
            matched_value=ioc.value,
            confidence=1.0,
            detail=f"pattern '{rule.pattern}' found in value",
        )

    def _evaluate_regex_rule(self, rule: DetectionRule, ioc: IOCRecord) -> RuleMatchResult | None:
        compiled = self._compiled_regex.get(rule.rule_id)
        if compiled is None:
            return None
        candidate_text = ioc.value[:MAX_REGEX_MATCH_INPUT_CHARS]
        if not compiled.search(candidate_text):
            return None
        return RuleMatchResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            matched=True,
            ioc_id=ioc.ioc_id,
            matched_value=ioc.value,
            confidence=1.0,
            detail=f"regex '{rule.regex}' matched value",
        )

    def _evaluate_threshold_rule(
        self, rule: DetectionRule, iocs: list[IOCRecord]
    ) -> RuleMatchResult | None:
        observed = sum(1 for ioc in iocs if ioc.ioc_type == rule.threshold_ioc_type)
        assert rule.threshold_value is not None and rule.threshold_operator is not None
        if not _compare_threshold(observed, rule.threshold_operator, rule.threshold_value):
            return None
        return RuleMatchResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            matched=True,
            confidence=1.0,
            detail=(
                f"observed count {observed} {rule.threshold_operator.value} "
                f"{rule.threshold_value} for {rule.threshold_ioc_type}"
            ),
        )

    def _evaluate_composite_rule(
        self, rule: DetectionRule, matched_by_rule: dict[str, bool]
    ) -> RuleMatchResult | None:
        assert rule.composite_operator is not None  # guaranteed by validate_rule_shape
        member_results = [
            matched_by_rule.get(rule_id, False) for rule_id in rule.composite_rule_ids
        ]
        if rule.composite_operator is CompositeOperator.AND:
            satisfied = all(member_results) and bool(member_results)
        else:
            satisfied = any(member_results)
        if not satisfied:
            return None
        return RuleMatchResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            matched=True,
            confidence=1.0,
            detail=f"composite {rule.composite_operator.value} of {rule.composite_rule_ids}",
        )


def _compare_threshold(observed: int, operator: ThresholdOperator, value: int) -> bool:
    if operator is ThresholdOperator.GREATER_THAN_OR_EQUAL:
        return observed >= value
    if operator is ThresholdOperator.GREATER_THAN:
        return observed > value
    return observed == value


__all__ = [
    "DetectionRuleEngine",
    "MAX_REGEX_MATCH_INPUT_CHARS",
    "UnsafeRegexError",
    "validate_regex_safety",
]
