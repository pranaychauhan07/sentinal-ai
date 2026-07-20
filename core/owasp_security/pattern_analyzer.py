"""``PatternSourceAnalyzer`` — the pattern-based half of the "Vulnerability
Detection Engine" for languages this project has no AST facility for
(JavaScript, TypeScript, Java — docs/adr/0021's explicit scope decision).
Runs `pattern_rules.DEFAULT_PATTERN_RULES` line-by-line via
`rule_engine.RuleEngine.evaluate_text`, so every finding carries a real
line number (unlike a whole-file regex scan).
"""

from __future__ import annotations

from core.owasp_security.models import SourceFinding
from core.owasp_security.pattern_rules import DEFAULT_PATTERN_RULES
from core.owasp_security.rule_engine import RuleEngine
from core.owasp_security.text_utils import sanitize_snippet


class PatternSourceAnalyzer:
    def __init__(self, *, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine(list(DEFAULT_PATTERN_RULES))

    def analyze(self, source: str, *, file_path: str, language: str) -> list[SourceFinding]:
        findings: list[SourceFinding] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            if not line.strip():
                continue
            for match in self._rule_engine.evaluate_text(line, language=language):
                findings.append(
                    SourceFinding(
                        file_path=file_path,
                        line_number=line_number,
                        category=match.category,
                        owasp_category=match.owasp_category,
                        cwe_id=match.cwe_id,
                        severity=match.severity,
                        confidence=match.confidence,
                        code_snippet=sanitize_snippet(line.strip()),
                        explanation=match.explanation,
                        recommendation=match.recommendation,
                        matched_rule_ids=(match.rule_id,),
                        is_ast_based=False,
                    )
                )
        return findings
