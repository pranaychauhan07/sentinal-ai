"""Unit tests for core/threat_intel/rule_validation.py."""

from __future__ import annotations

import pytest

from core.threat_intel.exceptions import RuleValidationError, UnsafeRegexError
from core.threat_intel.models import (
    CompositeOperator,
    DetectionRule,
    RuleType,
    ThresholdOperator,
)
from core.threat_intel.rule_validation import validate_regex_safety, validate_rule_shape


@pytest.mark.unit
def test_validate_regex_safety_accepts_bounded_pattern() -> None:
    validate_regex_safety(r"\b[A-Fa-f0-9]{40}\b")  # must not raise


@pytest.mark.unit
def test_validate_regex_safety_rejects_nested_quantifiers() -> None:
    with pytest.raises(UnsafeRegexError):
        validate_regex_safety(r"(a+)+$")


@pytest.mark.unit
def test_validate_regex_safety_rejects_overlong_pattern() -> None:
    with pytest.raises(UnsafeRegexError):
        validate_regex_safety("a" * 501)


@pytest.mark.unit
def test_validate_regex_safety_rejects_uncompilable_pattern() -> None:
    with pytest.raises(UnsafeRegexError):
        validate_regex_safety("[unclosed")


@pytest.mark.unit
def test_validate_rule_shape_pattern_requires_pattern_field() -> None:
    rule = DetectionRule(rule_id="r1", name="test", rule_type=RuleType.PATTERN)
    with pytest.raises(RuleValidationError):
        validate_rule_shape(rule)


@pytest.mark.unit
def test_validate_rule_shape_regex_validates_pattern_safety() -> None:
    rule = DetectionRule(rule_id="r1", name="test", rule_type=RuleType.REGEX, regex=r"(a+)+")
    with pytest.raises(UnsafeRegexError):
        validate_rule_shape(rule)


@pytest.mark.unit
def test_validate_rule_shape_threshold_requires_fields() -> None:
    rule = DetectionRule(rule_id="r1", name="test", rule_type=RuleType.THRESHOLD)
    with pytest.raises(RuleValidationError):
        validate_rule_shape(rule)


@pytest.mark.unit
def test_validate_rule_shape_threshold_accepts_complete_definition() -> None:
    from core.threat_intel.models import IOCType

    rule = DetectionRule(
        rule_id="r1",
        name="test",
        rule_type=RuleType.THRESHOLD,
        threshold_ioc_type=IOCType.IPV4,
        threshold_operator=ThresholdOperator.GREATER_THAN_OR_EQUAL,
        threshold_value=5,
    )
    validate_rule_shape(rule)  # must not raise


@pytest.mark.unit
def test_validate_rule_shape_composite_requires_known_rule_ids() -> None:
    rule = DetectionRule(
        rule_id="r2",
        name="test",
        rule_type=RuleType.COMPOSITE,
        composite_operator=CompositeOperator.AND,
        composite_rule_ids=("unregistered",),
    )
    with pytest.raises(RuleValidationError):
        validate_rule_shape(rule, known_rule_ids=frozenset())


@pytest.mark.unit
def test_validate_rule_shape_composite_accepts_known_rule_ids() -> None:
    rule = DetectionRule(
        rule_id="r2",
        name="test",
        rule_type=RuleType.COMPOSITE,
        composite_operator=CompositeOperator.AND,
        composite_rule_ids=("r1",),
    )
    validate_rule_shape(rule, known_rule_ids=frozenset({"r1"}))  # must not raise
