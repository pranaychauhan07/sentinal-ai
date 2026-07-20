"""``PythonAstAnalyzer`` — the task's named "AST Builder" + AST-based half
of the "Vulnerability Detection Engine" for Python source. Builds a real
`ast.AST` via `ast.parse()` and runs `python_ast_rules.DEFAULT_PYTHON_AST_RULES`
against it via `rule_engine.RuleEngine.evaluate_ast`.

A genuine Python `SyntaxError` (malformed source) raises
`AstParseError` — caught by `analysis_engine.py` and converted into a
degraded, zero-finding result, never fatal to the whole artifact
(constitution §1.7).
"""

from __future__ import annotations

import ast

from core.owasp_security.exceptions import AstParseError
from core.owasp_security.models import SourceFinding, SourceLanguage
from core.owasp_security.python_ast_rules import DEFAULT_PYTHON_AST_RULES
from core.owasp_security.rule_engine import RuleEngine
from core.owasp_security.text_utils import sanitize_snippet


def build_ast(source: str, *, filename: str) -> ast.AST:
    """The task's named "AST Builder" — parses `source` into an `ast.AST`.
    Raises `AstParseError` on a genuine syntax error rather than letting a
    raw `SyntaxError` propagate, so callers have one exception type to
    catch (constitution §9)."""
    try:
        return ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:
        raise AstParseError(f"Could not parse '{filename}' as Python: {exc}") from exc


class PythonAstAnalyzer:
    def __init__(self, *, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine(list(DEFAULT_PYTHON_AST_RULES))

    def analyze(self, source: str, *, file_path: str) -> list[SourceFinding]:
        """Raises `AstParseError` if `source` is not syntactically valid
        Python — the caller (`analysis_engine.py`) is responsible for
        catching this and degrading gracefully."""
        tree = build_ast(source, filename=file_path)
        source_lines = source.splitlines()
        matches = self._rule_engine.evaluate_ast(
            tree, source_lines, language=SourceLanguage.PYTHON.value
        )

        findings: list[SourceFinding] = []
        for match in matches:
            findings.append(
                SourceFinding(
                    file_path=file_path,
                    line_number=match.line_number,
                    category=match.category,
                    owasp_category=match.owasp_category,
                    cwe_id=match.cwe_id,
                    severity=match.severity,
                    confidence=match.confidence,
                    code_snippet=sanitize_snippet(match.matched_text),
                    explanation=match.explanation,
                    recommendation=match.recommendation,
                    matched_rule_ids=(match.rule_id,),
                    is_ast_based=True,
                )
            )
        return findings
