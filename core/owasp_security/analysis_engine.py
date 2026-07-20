"""``SourceCodeAnalysisEngine`` — the orchestrator (the task's named
"Pipeline": Source Code -> Language Detection -> AST Parsing -> Rule
Matching -> Finding Generation -> Confidence Calculation, with Persistence/
Case Integration/Metrics happening one layer up in
`core/services/owasp_security_service.py` and `core/services/case_service.py`).

Defends against four failure classes without ever aborting the whole
artifact (constitution §1.7):

1. **Oversized input** — a configurable max-line/max-character guard raises
   `OversizedSourceInputError` before any per-file work starts.
2. **Unsupported/undetected language** — `LanguageDetector` returning
   `SourceLanguage.UNKNOWN` degrades to a zero-finding `SastAdvice`
   (`parse_degraded=True`) rather than guessing a language.
3. **Malformed source (a genuine syntax error)** — `AstParseError` from
   `PythonAstAnalyzer` degrades to a zero-finding result with an explicit
   "could not parse" explanation, never a crash.
4. **Log-injection-shaped content** — every code snippet is sanitized
   (control characters/embedded newlines stripped) before it reaches a log
   line or the advice text itself. This package never executes, `eval`s, or
   runs any analyzed source code.
"""

from __future__ import annotations

from core.logging import get_logger
from core.owasp_security.exceptions import (
    AstParseError,
    OversizedSourceInputError,
    UnsupportedLanguageError,
)
from core.owasp_security.finding_generator import FindingGenerator
from core.owasp_security.language_detector import LanguageDetector
from core.owasp_security.metrics import SastMetricsCollector
from core.owasp_security.models import SastAdvice, SastSeverity, SourceFinding
from core.owasp_security.risk_assessment import RiskAssessmentEngine
from core.owasp_security.secure_coding_advisor import SecureCodingAdvisor
from core.owasp_security.text_utils import sanitize_snippet
from core.owasp_security.vulnerability_detection_engine import VulnerabilityDetectionEngine

_logger = get_logger(__name__)

#: Re-exported for callers/tests expecting this package's sanitization
#: helper at the orchestrator level (mirrors `core.owasp_web.advisory_engine.
#: sanitize_text`'s naming precedent) — applies only to short snippets, never
#: to a whole multi-line source file.
sanitize_text = sanitize_snippet


class SourceCodeAnalysisEngine:
    def __init__(
        self,
        *,
        max_lines: int,
        max_total_chars: int,
        language_detector: LanguageDetector | None = None,
        detection_engine: VulnerabilityDetectionEngine | None = None,
        secure_coding_advisor: SecureCodingAdvisor | None = None,
        finding_generator: FindingGenerator | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        metrics: SastMetricsCollector | None = None,
    ) -> None:
        self._max_lines = max_lines
        self._max_total_chars = max_total_chars
        self._language_detector = language_detector or LanguageDetector()
        self._detection_engine = detection_engine or VulnerabilityDetectionEngine()
        self._secure_coding_advisor = secure_coding_advisor or SecureCodingAdvisor()
        self._finding_generator = finding_generator or FindingGenerator()
        self._risk_engine = risk_engine or RiskAssessmentEngine()
        self._metrics = metrics or SastMetricsCollector()

    def analyze(self, source: str, *, filename: str) -> SastAdvice:
        lines = source.splitlines()
        if len(lines) > self._max_lines or len(source) > self._max_total_chars:
            raise OversizedSourceInputError(
                "Source code input exceeds the configured maximum "
                f"({self._max_lines} lines / {self._max_total_chars} characters).",
                details={"line_count": len(lines), "max_lines": self._max_lines},
            )

        language = self._language_detector.detect(filename=filename, source_text=source)
        self._metrics.record_file_analyzed(len(lines))

        source_findings: list[SourceFinding] = []
        parse_degraded = False
        overall_explanation_prefix = ""
        try:
            # NOTE: `source` is passed unsanitized — AST parsing requires the
            # file's real newline structure. Sanitization happens per-finding,
            # on the short extracted `code_snippet` only (python_ast_analyzer.py/
            # pattern_analyzer.py), never on the whole source (constitution §10's
            # log-injection guard would otherwise destroy every multi-line file).
            source_findings = self._detection_engine.analyze(
                source, file_path=filename, language=language
            )
        except UnsupportedLanguageError as exc:
            parse_degraded = True
            overall_explanation_prefix = (
                f"Language could not be determined for '{filename}'; no analysis performed. "
            )
            _logger.warning("sast_unsupported_language", filename=filename, error=str(exc))
        except AstParseError as exc:
            parse_degraded = True
            overall_explanation_prefix = f"'{filename}' could not be parsed as Python: {exc}. "
            _logger.warning("sast_parse_degraded", filename=filename, error=str(exc))

        for finding in source_findings:
            self._metrics.record_finding(finding.category.value)
            for rule_id in finding.matched_rule_ids:
                self._metrics.record_rule_match(rule_id)

        recommendations = self._secure_coding_advisor.advise(source_findings)
        sast_findings = self._finding_generator.generate(source_findings)
        overall_risk_level, overall_confidence, overall_explanation, _dimensions = (
            self._risk_engine.assess(
                findings=sast_findings, distinct_sources={f.source for f in sast_findings}
            )
        )

        if parse_degraded:
            overall_risk_level = SastSeverity.INFO
            overall_confidence = 0.0
            overall_explanation = overall_explanation_prefix + overall_explanation

        return SastAdvice(
            language=language,
            source_findings=tuple(source_findings),
            secure_coding_recommendations=tuple(recommendations),
            sast_findings=tuple(sast_findings),
            overall_risk_level=overall_risk_level,
            overall_confidence=overall_confidence,
            overall_explanation=overall_explanation,
            parse_degraded=parse_degraded,
            total_line_count=len(lines),
        )
