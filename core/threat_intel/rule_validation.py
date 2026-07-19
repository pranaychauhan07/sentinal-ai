"""Detection-rule structural and regex-safety validation — the guardrail
`core.threat_intel.rules.DetectionRuleEngine.register_rule` runs every
`DetectionRule` through before it can ever be evaluated (constitution §10,
"protect against catastrophic regex", enforced structurally per docs/adr/0012).
"""

from __future__ import annotations

import re

from core.threat_intel.exceptions import RuleValidationError, UnsafeRegexError
from core.threat_intel.models import CompositeOperator, DetectionRule, RuleType, ThresholdOperator

#: A pattern longer than this is rejected outright — long, complex regexes
#: are exactly the shape that hides catastrophic backtracking.
MAX_REGEX_PATTERN_LENGTH = 500

#: Heuristic signatures of nested/overlapping quantifiers — the classic
#: catastrophic-backtracking shape (e.g. `(a+)+`, `(a*)*`, `(a+)*`). This is
#: a conservative, best-effort static check, not a full NFA analysis; it is
#: paired with the runtime length cap
#: (`Settings.threat_intel_max_regex_input_chars`) as defense in depth.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


def validate_regex_safety(pattern: str) -> None:
    """Raise `UnsafeRegexError` if `pattern` is too long or exhibits a
    nested-quantifier shape prone to catastrophic backtracking. Raise
    `UnsafeRegexError` (not a bare `re.error`) if the pattern fails to
    compile at all, so callers catch one exception type."""
    if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        raise UnsafeRegexError(
            f"Regex pattern of {len(pattern)} characters exceeds the "
            f"{MAX_REGEX_PATTERN_LENGTH}-character limit.",
            details={"length": len(pattern)},
        )
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise UnsafeRegexError(
            "Regex pattern contains a nested/overlapping quantifier shape "
            "prone to catastrophic backtracking.",
            details={"pattern": pattern},
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise UnsafeRegexError(
            f"Regex pattern failed to compile: {exc}", details={"pattern": pattern}
        ) from exc


def validate_rule_shape(rule: DetectionRule, known_rule_ids: frozenset[str] = frozenset()) -> None:
    """Structural validation of `rule` for its declared `rule_type`
    (constitution §5, "a tool validates its own inputs"). Regex safety is
    delegated to `validate_regex_safety`."""
    if rule.rule_type is RuleType.PATTERN and not rule.pattern:
        raise RuleValidationError(f"Rule {rule.rule_id!r}: PATTERN rule requires 'pattern'.")

    if rule.rule_type is RuleType.REGEX:
        if not rule.regex:
            raise RuleValidationError(f"Rule {rule.rule_id!r}: REGEX rule requires 'regex'.")
        validate_regex_safety(rule.regex)

    if rule.rule_type is RuleType.THRESHOLD:
        if rule.threshold_ioc_type is None:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: THRESHOLD rule requires 'threshold_ioc_type'."
            )
        if rule.threshold_value is None or rule.threshold_value < 1:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: THRESHOLD rule requires a positive 'threshold_value'."
            )
        if rule.threshold_operator is None:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: THRESHOLD rule requires 'threshold_operator'."
            )
        if rule.threshold_operator not in ThresholdOperator:
            raise RuleValidationError(f"Rule {rule.rule_id!r}: unknown threshold operator.")

    if rule.rule_type is RuleType.COMPOSITE:
        if not rule.composite_rule_ids:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: COMPOSITE rule requires 'composite_rule_ids'."
            )
        if rule.composite_operator is None:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: COMPOSITE rule requires 'composite_operator'."
            )
        if rule.composite_operator not in CompositeOperator:
            raise RuleValidationError(f"Rule {rule.rule_id!r}: unknown composite operator.")
        missing = set(rule.composite_rule_ids) - known_rule_ids
        if missing:
            raise RuleValidationError(
                f"Rule {rule.rule_id!r}: composite_rule_ids reference unregistered rules: "
                f"{sorted(missing)}."
            )
