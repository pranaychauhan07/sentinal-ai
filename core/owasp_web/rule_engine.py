"""``RuleEngine`` — the generic, data-driven detection engine this package's
extensibility seam: future OWASP rule expansion must not require
architecture changes. Adding a detection later means adding a `Rule` object
to `header_rules.py`/`misconfig_rules.py` (or a caller's own module) — never
touching this file.

Functionally identical to `core.linux_advisor.rule_engine` (same
`regex`/`literal_substring`/`callable_signature` matcher kinds, same
metadata/version/priority/enable-disable shape) but deliberately not
imported from there — leaf packages never share code sideways
(docs/dependency-rules.md rule 10), each owns its own copy of this small,
generic engine.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from core.owasp_web.models import MatcherKind, OwaspCategory, RuleMatch, WebSecuritySeverity


class Matcher(BaseModel):
    """Tagged-union matcher spec on a `Rule`. Which fields are required
    depends on `kind`: `regex`/`literal_substring` require `pattern`;
    `callable_signature` requires `callable_name` — enforced in
    `Rule.model_post_init`."""

    model_config = ConfigDict(frozen=True)

    kind: MatcherKind
    pattern: str | None = None
    callable_name: str | None = None


class Rule(BaseModel):
    """One detection rule. `matcher` is the discriminated-union field the
    engine dispatches on. `version`/`enabled` support the same soft-disable/
    versioning convention `core.parsers.registry.ParserRegistration` already
    established."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    matcher: Matcher
    explanation: str
    recommendation: str | None = None
    priority: int = 0
    version: str = "1.0.0"
    enabled: bool = True

    def model_post_init(self, __context: object) -> None:
        text_kind = self.matcher.kind in (MatcherKind.REGEX, MatcherKind.LITERAL_SUBSTRING)
        if text_kind and not self.matcher.pattern:
            raise ValueError(
                f"Rule '{self.id}': matcher of kind {self.matcher.kind} needs a pattern."
            )
        callable_kind = self.matcher.kind is MatcherKind.CALLABLE_SIGNATURE
        if callable_kind and not self.matcher.callable_name:
            raise ValueError(f"Rule '{self.id}': callable_signature matcher needs callable_name.")


#: Named predicates a `callable_signature` matcher can reference —
#: registered here rather than imported ad hoc, so `Rule` stays a plain,
#: serializable Pydantic model with no embedded closures.
CallablePredicate = Callable[[str], str | None]

_CALLABLE_REGISTRY: dict[str, CallablePredicate] = {}


def register_callable(name: str, predicate: CallablePredicate) -> None:
    """Register a named predicate for `callable_signature` rules.
    `predicate(text) -> matched_text | None` — returns the matched substring
    (truthy) on a hit, `None` on no match. Re-registering the same name
    overwrites the previous entry."""
    _CALLABLE_REGISTRY[name] = predicate


def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


class RuleEngine:
    """Register/enable/disable/list rules; `evaluate(text)` returns every
    matching rule's `RuleMatch`, sorted by priority (highest first)."""

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

    def evaluate(self, text: str) -> list[RuleMatch]:
        """Runs every enabled rule against `text`, sorted by rule priority
        (highest first). Never executes/evals `text` — pure regex/substring/
        predicate checks only (constitution §10)."""
        matches: list[RuleMatch] = []
        for rule in self.list_rules(include_disabled=False):
            matched_text = self._match_one(rule, text)
            if matched_text is None:
                continue
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    explanation=rule.explanation,
                    recommendation=rule.recommendation,
                    matched_text=matched_text,
                )
            )
        return matches

    def _match_one(self, rule: Rule, text: str) -> str | None:
        matcher = rule.matcher
        if matcher.kind is MatcherKind.REGEX:
            assert matcher.pattern is not None  # noqa: S101 - guaranteed by Rule.model_post_init
            found = _compiled(matcher.pattern).search(text)
            return found.group(0) if found else None
        if matcher.kind is MatcherKind.LITERAL_SUBSTRING:
            assert matcher.pattern is not None  # noqa: S101 - guaranteed by Rule.model_post_init
            if matcher.pattern.lower() in text.lower():
                return matcher.pattern
            return None
        if matcher.kind is MatcherKind.CALLABLE_SIGNATURE:
            assert matcher.callable_name is not None  # noqa: S101 - guaranteed by Rule.model_post_init
            predicate = _CALLABLE_REGISTRY.get(matcher.callable_name)
            if predicate is None:
                return None
            return predicate(text)
        return None
