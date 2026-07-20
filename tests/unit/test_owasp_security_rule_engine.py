"""Unit tests for core/owasp_security/rule_engine.py — the generic engine
extended with the `ast_predicate` matcher kind."""

from __future__ import annotations

import ast

import pytest

from core.owasp_security.models import MatcherKind, OwaspCategory, VulnerabilityCategory
from core.owasp_security.rule_engine import (
    Matcher,
    Rule,
    RuleEngine,
    register_ast_predicate,
    register_callable,
)

pytestmark = pytest.mark.unit


def _text_rule(**overrides: object) -> Rule:
    defaults: dict[str, object] = {
        "id": "test_regex",
        "name": "Test regex rule",
        "category": VulnerabilityCategory.INSECURE_CONFIGURATION,
        "severity": "high",
        "confidence": 0.8,
        "matcher": Matcher(kind=MatcherKind.REGEX, pattern=r"danger\d+"),
        "explanation": "test explanation",
        "priority": 10,
    }
    defaults.update(overrides)
    return Rule(**defaults)  # type: ignore[arg-type]


def test_rule_derives_owasp_category_and_cwe_automatically() -> None:
    rule = _text_rule()
    assert rule.owasp_category == OwaspCategory.A05_SECURITY_MISCONFIGURATION
    assert rule.cwe_id == "CWE-16"


def test_regex_rule_matches() -> None:
    engine = RuleEngine([_text_rule()])
    matches = engine.evaluate_text("this is danger42 right here")
    assert len(matches) == 1
    assert matches[0].rule_id == "test_regex"
    assert matches[0].matched_text == "danger42"


def test_regex_rule_no_match() -> None:
    engine = RuleEngine([_text_rule()])
    assert engine.evaluate_text("perfectly safe text") == []


def test_literal_substring_rule() -> None:
    rule = _text_rule(
        id="literal", matcher=Matcher(kind=MatcherKind.LITERAL_SUBSTRING, pattern="nopasswd")
    )
    engine = RuleEngine([rule])
    assert len(engine.evaluate_text("some text with NOPASSWD inside")) == 1


def test_callable_signature_rule() -> None:
    register_callable("owasp_sec_test_true", lambda text: "matched!" if "trigger" in text else None)
    rule = _text_rule(
        id="callable_rule",
        matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name="owasp_sec_test_true"),
    )
    engine = RuleEngine([rule])
    assert len(engine.evaluate_text("has a trigger word")) == 1
    assert engine.evaluate_text("no keyword") == []


def test_ast_predicate_rule() -> None:
    def _predicate(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
        return [
            (node.lineno, source_lines[node.lineno - 1])
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ]

    register_ast_predicate("owasp_sec_test_eval", _predicate)
    rule = _text_rule(
        id="ast_rule",
        matcher=Matcher(kind=MatcherKind.AST_PREDICATE, ast_predicate_name="owasp_sec_test_eval"),
    )
    engine = RuleEngine([rule])
    source = "x = eval(y)\n"
    tree = ast.parse(source)
    matches = engine.evaluate_ast(tree, source.splitlines())
    assert len(matches) == 1
    assert matches[0].line_number == 1


def test_ast_predicate_unregistered_name_never_matches() -> None:
    rule = _text_rule(
        id="ast_missing",
        matcher=Matcher(kind=MatcherKind.AST_PREDICATE, ast_predicate_name="does_not_exist"),
    )
    engine = RuleEngine([rule])
    tree = ast.parse("x = 1\n")
    assert engine.evaluate_ast(tree, ["x = 1"]) == []


def test_language_filter_excludes_non_matching_language() -> None:
    rule = _text_rule(id="js_only", languages=("javascript",))
    engine = RuleEngine([rule])
    assert engine.evaluate_text("danger1", language="python") == []
    assert len(engine.evaluate_text("danger1", language="javascript")) == 1


def test_disabled_rule_never_matches() -> None:
    engine = RuleEngine([_text_rule()])
    engine.disable("test_regex")
    assert engine.evaluate_text("danger99") == []


def test_reenabled_rule_matches_again() -> None:
    engine = RuleEngine([_text_rule()])
    engine.disable("test_regex")
    engine.enable("test_regex")
    assert len(engine.evaluate_text("danger99")) == 1


def test_matches_sorted_by_priority_descending() -> None:
    low = _text_rule(
        id="low_priority", priority=1, matcher=Matcher(kind=MatcherKind.REGEX, pattern="x")
    )
    high = _text_rule(
        id="high_priority", priority=99, matcher=Matcher(kind=MatcherKind.REGEX, pattern="x")
    )
    engine = RuleEngine([low, high])
    matches = engine.evaluate_text("x")
    assert [m.rule_id for m in matches] == ["high_priority", "low_priority"]


def test_disable_unknown_rule_raises() -> None:
    engine = RuleEngine()
    with pytest.raises(KeyError):
        engine.disable("nonexistent")


def test_regex_matcher_requires_pattern() -> None:
    with pytest.raises(ValueError, match="needs a pattern"):
        _text_rule(matcher=Matcher(kind=MatcherKind.REGEX, pattern=None))


def test_callable_matcher_requires_callable_name() -> None:
    with pytest.raises(ValueError, match="needs callable_name"):
        _text_rule(matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name=None))


def test_ast_predicate_matcher_requires_predicate_name() -> None:
    with pytest.raises(ValueError, match="needs ast_predicate_name"):
        _text_rule(matcher=Matcher(kind=MatcherKind.AST_PREDICATE, ast_predicate_name=None))


def test_list_rules_include_disabled_flag() -> None:
    engine = RuleEngine([_text_rule()])
    engine.disable("test_regex")
    assert len(engine.list_rules(include_disabled=True)) == 1
    assert len(engine.list_rules(include_disabled=False)) == 0
