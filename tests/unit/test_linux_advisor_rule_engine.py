"""Unit tests for core/linux_advisor/rule_engine.py — the generic,
data-driven RuleEngine that's the task's extensibility seam."""

from __future__ import annotations

import pytest

from core.linux_advisor.models import LinuxAdvisorSeverity, MatcherKind
from core.linux_advisor.rule_engine import Matcher, Rule, RuleEngine, register_callable

pytestmark = pytest.mark.unit


def _regex_rule(**overrides: object) -> Rule:
    defaults: dict[str, object] = {
        "id": "test_regex",
        "name": "Test regex rule",
        "category": "test",
        "severity": LinuxAdvisorSeverity.HIGH,
        "confidence": 0.8,
        "matcher": Matcher(kind=MatcherKind.REGEX, pattern=r"danger\d+"),
        "explanation": "test explanation",
        "priority": 10,
    }
    defaults.update(overrides)
    return Rule(**defaults)  # type: ignore[arg-type]


def test_regex_rule_matches() -> None:
    engine = RuleEngine([_regex_rule()])
    matches = engine.evaluate("this is danger42 right here")
    assert len(matches) == 1
    assert matches[0].rule_id == "test_regex"
    assert matches[0].matched_text == "danger42"


def test_regex_rule_no_match() -> None:
    engine = RuleEngine([_regex_rule()])
    assert engine.evaluate("perfectly safe text") == []


def test_literal_substring_rule() -> None:
    rule = _regex_rule(
        id="literal",
        matcher=Matcher(kind=MatcherKind.LITERAL_SUBSTRING, pattern="NOPASSWD"),
    )
    engine = RuleEngine([rule])
    matches = engine.evaluate("some text with nopasswd inside (case-insensitive)")
    assert len(matches) == 1


def test_callable_signature_rule() -> None:
    register_callable("always_true_test", lambda text: "matched!" if "trigger" in text else None)
    rule = _regex_rule(
        id="callable_rule",
        matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name="always_true_test"),
    )
    engine = RuleEngine([rule])
    assert len(engine.evaluate("this text has a trigger word")) == 1
    assert engine.evaluate("no keyword here") == []


def test_callable_signature_unregistered_name_never_matches() -> None:
    rule = _regex_rule(
        id="missing_callable",
        matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name="does_not_exist"),
    )
    engine = RuleEngine([rule])
    assert engine.evaluate("anything") == []


def test_disabled_rule_never_matches() -> None:
    engine = RuleEngine([_regex_rule()])
    engine.disable("test_regex")
    assert engine.evaluate("danger99") == []


def test_reenabled_rule_matches_again() -> None:
    engine = RuleEngine([_regex_rule()])
    engine.disable("test_regex")
    engine.enable("test_regex")
    assert len(engine.evaluate("danger99")) == 1


def test_matches_sorted_by_priority_descending() -> None:
    low = _regex_rule(
        id="low_priority", priority=1, matcher=Matcher(kind=MatcherKind.REGEX, pattern="x")
    )
    high = _regex_rule(
        id="high_priority", priority=99, matcher=Matcher(kind=MatcherKind.REGEX, pattern="x")
    )
    engine = RuleEngine([low, high])
    matches = engine.evaluate("x")
    assert [m.rule_id for m in matches] == ["high_priority", "low_priority"]


def test_disable_unknown_rule_raises() -> None:
    engine = RuleEngine()
    with pytest.raises(KeyError):
        engine.disable("nonexistent")


def test_regex_matcher_requires_pattern() -> None:
    with pytest.raises(ValueError, match="needs a pattern"):
        _regex_rule(matcher=Matcher(kind=MatcherKind.REGEX, pattern=None))


def test_callable_matcher_requires_callable_name() -> None:
    with pytest.raises(ValueError, match="needs callable_name"):
        _regex_rule(matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name=None))


def test_list_rules_include_disabled_flag() -> None:
    engine = RuleEngine([_regex_rule()])
    engine.disable("test_regex")
    assert len(engine.list_rules(include_disabled=True)) == 1
    assert len(engine.list_rules(include_disabled=False)) == 0
