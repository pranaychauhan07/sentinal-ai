"""``MisconfigurationDetector`` — runs `misconfig_rules.DEFAULT_MISCONFIG_RULES`
against a generic (non-header, non-cookie, non-JWT) line of evidence:
response-body snippets, web server log lines, URL paths, or TLS
configuration metadata. `None` (no matched rule) is a real, reachable
"nothing concerning found" outcome.
"""

from __future__ import annotations

from core.owasp_web.misconfig_rules import DEFAULT_MISCONFIG_RULES
from core.owasp_web.models import MisconfigurationFinding, severity_rank
from core.owasp_web.rule_engine import RuleEngine


class MisconfigurationDetector:
    def __init__(self, *, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine(list(DEFAULT_MISCONFIG_RULES))

    def analyze(self, text: str) -> MisconfigurationFinding | None:
        matches = self._rule_engine.evaluate(text)
        if not matches:
            return None
        highest = max(matches, key=lambda m: severity_rank(m.severity))
        return MisconfigurationFinding(
            raw_text=text,
            category=highest.category,
            severity=highest.severity,
            confidence=highest.confidence,
            explanation=highest.explanation,
            recommendation=highest.recommendation,
            matched_rule_ids=tuple(m.rule_id for m in matches),
        )
