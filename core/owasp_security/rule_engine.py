"""``RuleEngine`` — the generic, data-driven detection engine that's this
package's extensibility seam (the task's named "Rule Engine" requirement:
versioning, priority, categories, OWASP mapping, CWE mapping, severity,
enable/disable, metadata, composable rules, future custom rule support).

Supports four matcher kinds (`core.owasp_security.models.MatcherKind`):
`regex`/`literal_substring`/`callable_signature` (text-based, functionally
identical to `core.owasp_web.rule_engine`'s shape but never imported from it
— leaves own their own copy) plus `ast_predicate` — a named AST-visitor
predicate for Python source, registered via `register_ast_predicate` for
the same reason `callable_signature` predicates are registered by name
rather than embedded as closures: `Rule` stays a plain, serializable
Pydantic model.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator

from pydantic import BaseModel, ConfigDict, Field

from core.owasp_security.models import (
    CATEGORY_CWE_MAP,
    CATEGORY_OWASP_MAP,
    MatcherKind,
    OwaspCategory,
    RuleMatch,
    SastSeverity,
    VulnerabilityCategory,
)


class Matcher(BaseModel):
    """Tagged-union matcher spec on a `Rule`. `regex`/`literal_substring`
    require `pattern`; `callable_signature` requires `callable_name`;
    `ast_predicate` requires `ast_predicate_name` — enforced in
    `Rule.model_post_init`."""

    model_config = ConfigDict(frozen=True)

    kind: MatcherKind
    pattern: str | None = None
    callable_name: str | None = None
    ast_predicate_name: str | None = None


class Rule(BaseModel):
    """One detection rule. `category` determines `owasp_category`/`cwe_id`
    automatically via `CATEGORY_OWASP_MAP`/`CATEGORY_CWE_MAP` unless
    explicitly overridden — every rule is guaranteed a consistent OWASP/CWE
    mapping without repeating it at every call site."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    category: VulnerabilityCategory
    severity: SastSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    matcher: Matcher
    explanation: str
    recommendation: str | None = None
    languages: tuple[str, ...] = ()
    priority: int = 0
    version: str = "1.0.0"
    enabled: bool = True

    @property
    def owasp_category(self) -> OwaspCategory:
        return CATEGORY_OWASP_MAP[self.category]

    @property
    def cwe_id(self) -> str:
        return CATEGORY_CWE_MAP[self.category]

    def model_post_init(self, __context: object) -> None:
        text_kind = self.matcher.kind in (MatcherKind.REGEX, MatcherKind.LITERAL_SUBSTRING)
        if text_kind and not self.matcher.pattern:
            raise ValueError(
                f"Rule '{self.id}': matcher of kind {self.matcher.kind} needs a pattern."
            )
        if self.matcher.kind is MatcherKind.CALLABLE_SIGNATURE and not self.matcher.callable_name:
            raise ValueError(f"Rule '{self.id}': callable_signature matcher needs callable_name.")
        if self.matcher.kind is MatcherKind.AST_PREDICATE and not self.matcher.ast_predicate_name:
            raise ValueError(f"Rule '{self.id}': ast_predicate matcher needs ast_predicate_name.")


#: Named text predicates for `callable_signature` rules.
#: `predicate(text) -> matched_text | None`.
CallablePredicate = Callable[[str], str | None]
_CALLABLE_REGISTRY: dict[str, CallablePredicate] = {}

#: Named AST predicates for `ast_predicate` rules.
#: `predicate(tree, source_lines) -> [(line_number, snippet), ...]`.
AstPredicate = Callable[[ast.AST, list[str]], list[tuple[int, str]]]
_AST_PREDICATE_REGISTRY: dict[str, AstPredicate] = {}


def register_callable(name: str, predicate: CallablePredicate) -> None:
    """Register a named predicate for `callable_signature` rules.
    Re-registering the same name overwrites the previous entry."""
    _CALLABLE_REGISTRY[name] = predicate


def register_ast_predicate(name: str, predicate: AstPredicate) -> None:
    """Register a named predicate for `ast_predicate` rules.
    Re-registering the same name overwrites the previous entry."""
    _AST_PREDICATE_REGISTRY[name] = predicate


def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


class RuleEngine:
    """Register/enable/disable/list rules. `evaluate_text(text)` runs the
    three text-based matcher kinds; `evaluate_ast(tree, source_lines)` runs
    `ast_predicate` rules. Both return matches sorted by priority (highest
    first)."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules or []:
            self.register(rule)

    def register(self, rule: Rule) -> None:
        self._rules[rule.id] = rule

    def enable(self, rule_id: str) -> None:
        self._set_enabled(rule_id, True)

    def disable(self, rule_id: str) -> None:
        self._set_enabled(rule_id, False)

    def _set_enabled(self, rule_id: str, enabled: bool) -> None:
        rule = self._rules.get(rule_id)
        if rule is None:
            raise KeyError(f"No rule registered under id '{rule_id}'.")
        self._rules[rule_id] = rule.model_copy(update={"enabled": enabled})

    def list_rules(self, *, include_disabled: bool = True) -> tuple[Rule, ...]:
        rules: list[Rule] = list(self._rules.values())
        if not include_disabled:
            rules = [r for r in rules if r.enabled]
        return tuple(sorted(rules, key=lambda r: r.priority, reverse=True))

    def _applicable_rules(
        self, *, language: str | None, kinds: tuple[MatcherKind, ...]
    ) -> Iterator[Rule]:
        for rule in self.list_rules(include_disabled=False):
            if rule.matcher.kind not in kinds:
                continue
            if rule.languages and language is not None and language not in rule.languages:
                continue
            yield rule

    def evaluate_text(self, text: str, *, language: str | None = None) -> list[RuleMatch]:
        """Runs every enabled text-based rule against `text`. Never
        executes/evals `text` — pure regex/substring/predicate checks only
        (constitution §10)."""
        matches: list[RuleMatch] = []
        for rule in self._applicable_rules(
            language=language,
            kinds=(
                MatcherKind.REGEX,
                MatcherKind.LITERAL_SUBSTRING,
                MatcherKind.CALLABLE_SIGNATURE,
            ),
        ):
            matched_text = self._match_text(rule, text)
            if matched_text is None:
                continue
            matches.append(self._to_rule_match(rule, matched_text=matched_text))
        return matches

    def evaluate_ast(
        self, tree: ast.AST, source_lines: list[str], *, language: str | None = None
    ) -> list[RuleMatch]:
        """Runs every enabled `ast_predicate` rule against `tree`. Never
        executes/evals the source — pure AST traversal only."""
        matches: list[RuleMatch] = []
        for rule in self._applicable_rules(language=language, kinds=(MatcherKind.AST_PREDICATE,)):
            assert rule.matcher.ast_predicate_name is not None  # noqa: S101 - guaranteed by model_post_init
            predicate = _AST_PREDICATE_REGISTRY.get(rule.matcher.ast_predicate_name)
            if predicate is None:
                continue
            for line_number, snippet in predicate(tree, source_lines):
                matches.append(
                    self._to_rule_match(rule, matched_text=snippet, line_number=line_number)
                )
        return matches

    def _to_rule_match(
        self, rule: Rule, *, matched_text: str, line_number: int | None = None
    ) -> RuleMatch:
        return RuleMatch(
            rule_id=rule.id,
            category=rule.category,
            owasp_category=rule.owasp_category,
            cwe_id=rule.cwe_id,
            severity=rule.severity,
            confidence=rule.confidence,
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            matched_text=matched_text,
            line_number=line_number,
        )

    def _match_text(self, rule: Rule, text: str) -> str | None:
        matcher = rule.matcher
        if matcher.kind is MatcherKind.REGEX:
            assert matcher.pattern is not None  # noqa: S101 - guaranteed by model_post_init
            found = _compiled(matcher.pattern).search(text)
            return found.group(0) if found else None
        if matcher.kind is MatcherKind.LITERAL_SUBSTRING:
            assert matcher.pattern is not None  # noqa: S101 - guaranteed by model_post_init
            if matcher.pattern.lower() in text.lower():
                return matcher.pattern
            return None
        if matcher.kind is MatcherKind.CALLABLE_SIGNATURE:
            assert matcher.callable_name is not None  # noqa: S101 - guaranteed by model_post_init
            predicate = _CALLABLE_REGISTRY.get(matcher.callable_name)
            if predicate is None:
                return None
            return predicate(text)
        return None
