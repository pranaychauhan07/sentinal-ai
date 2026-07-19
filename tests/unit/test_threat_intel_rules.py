"""Unit tests for core/threat_intel/rules.py — DetectionRuleEngine."""

from __future__ import annotations

import pytest

from core.threat_intel.models import (
    CompositeOperator,
    DetectionRule,
    IOCRecord,
    IOCType,
    RuleType,
    ThresholdOperator,
)
from core.threat_intel.rules import DetectionRuleEngine


def _ioc(ioc_type: IOCType = IOCType.IPV4, value: str = "1.2.3.4") -> IOCRecord:
    return IOCRecord(ioc_type=ioc_type, value=value, raw_value=value, source="test")


@pytest.mark.unit
def test_pattern_rule_matches_substring() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(rule_id="p1", name="known-bad-tld", rule_type=RuleType.PATTERN, pattern=".ru")
    )
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "evil.ru")])
    assert len(matches) == 1
    assert matches[0].matched is True


@pytest.mark.unit
def test_pattern_rule_respects_ioc_type_filter() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(
            rule_id="p1",
            name="test",
            rule_type=RuleType.PATTERN,
            pattern="evil",
            ioc_types=(IOCType.DOMAIN,),
        )
    )
    matches = engine.evaluate([_ioc(IOCType.IPV4, "1.2.3.4")])
    assert matches == []


@pytest.mark.unit
def test_regex_rule_matches() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(rule_id="r1", name="private-range", rule_type=RuleType.REGEX, regex=r"^10\.")
    )
    matches = engine.evaluate([_ioc(IOCType.IPV4, "10.0.0.1")])
    assert len(matches) == 1


@pytest.mark.unit
def test_threshold_rule_matches_when_count_meets_operator() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(
            rule_id="t1",
            name="many-ips",
            rule_type=RuleType.THRESHOLD,
            threshold_ioc_type=IOCType.IPV4,
            threshold_operator=ThresholdOperator.GREATER_THAN_OR_EQUAL,
            threshold_value=2,
        )
    )
    matches = engine.evaluate([_ioc(value="1.1.1.1"), _ioc(value="2.2.2.2")])
    assert len(matches) == 1


@pytest.mark.unit
def test_threshold_rule_does_not_match_below_count() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(
            rule_id="t1",
            name="many-ips",
            rule_type=RuleType.THRESHOLD,
            threshold_ioc_type=IOCType.IPV4,
            threshold_operator=ThresholdOperator.GREATER_THAN_OR_EQUAL,
            threshold_value=5,
        )
    )
    matches = engine.evaluate([_ioc(value="1.1.1.1")])
    assert matches == []


@pytest.mark.unit
def test_composite_and_rule_requires_all_members() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(rule_id="p1", name="p1", rule_type=RuleType.PATTERN, pattern="evil")
    )
    engine.register_rule(
        DetectionRule(rule_id="p2", name="p2", rule_type=RuleType.PATTERN, pattern="nonexistent")
    )
    engine.register_rule(
        DetectionRule(
            rule_id="c1",
            name="composite",
            rule_type=RuleType.COMPOSITE,
            composite_operator=CompositeOperator.AND,
            composite_rule_ids=("p1", "p2"),
        )
    )
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "evil.com")])
    assert not any(m.rule_id == "c1" for m in matches)


@pytest.mark.unit
def test_composite_or_rule_matches_when_one_member_matches() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(rule_id="p1", name="p1", rule_type=RuleType.PATTERN, pattern="evil")
    )
    engine.register_rule(
        DetectionRule(rule_id="p2", name="p2", rule_type=RuleType.PATTERN, pattern="nonexistent")
    )
    engine.register_rule(
        DetectionRule(
            rule_id="c1",
            name="composite",
            rule_type=RuleType.COMPOSITE,
            composite_operator=CompositeOperator.OR,
            composite_rule_ids=("p1", "p2"),
        )
    )
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "evil.com")])
    assert any(m.rule_id == "c1" for m in matches)


@pytest.mark.unit
def test_disabled_rule_is_never_evaluated() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(rule_id="p1", name="p1", rule_type=RuleType.PATTERN, pattern="evil")
    )
    engine.disable_rule("p1")
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "evil.com")])
    assert matches == []


@pytest.mark.unit
def test_higher_priority_rules_evaluated_first_but_all_results_returned() -> None:
    engine = DetectionRuleEngine()
    engine.register_rule(
        DetectionRule(
            rule_id="low", name="low", rule_type=RuleType.PATTERN, pattern="evil", priority=1
        )
    )
    engine.register_rule(
        DetectionRule(
            rule_id="high", name="high", rule_type=RuleType.PATTERN, pattern="evil", priority=10
        )
    )
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "evil.com")])
    matched_ids = {m.rule_id for m in matches}
    assert matched_ids == {"low", "high"}
