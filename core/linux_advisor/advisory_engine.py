"""``LinuxSecurityAdvisoryEngine`` — the orchestrator. Takes the parser's raw
per-line text (`core.parsers.linux_command_parser.LinuxCommandInputParser`'s
`EvidenceRecord.raw_line` values), classifies each line (an `ls -l`-shaped
entry -> `permission_parser`/`permission_analyzer`; otherwise a command line
-> `command_analyzer`), runs `hardening_advisor.py` and `risk_assessment.py`
over the accumulated results, and returns the final `LinuxSecurityAdvice`.

Defends against three failure classes without ever aborting the whole
artifact (constitution §1.7):

1. **Oversized input** — a configurable max-line/max-character guard raises
   `OversizedLinuxAdvisorInputError` before any per-line work starts.
2. **Malformed individual lines** — an unparseable `ls -l` entry or a
   command string with broken quoting is skipped (counted in
   `skipped_line_count`), never aborts the rest.
3. **Command-injection / log-injection-shaped content** — every line is
   sanitized (control characters and embedded newlines stripped) before it
   ever appears in a log line or in the advice text itself. This package
   performs pure text analysis and never executes, `eval`s, or shells out to
   any analyzed content (constitution §10).
"""

from __future__ import annotations

import re

from core.linux_advisor.command_analyzer import CommandAnalyzer
from core.linux_advisor.exceptions import (
    InvalidPermissionStringError,
    OversizedLinuxAdvisorInputError,
)
from core.linux_advisor.hardening_advisor import HardeningAdvisor
from core.linux_advisor.metrics import LinuxAdvisorMetricsCollector
from core.linux_advisor.models import CommandRisk, LinuxSecurityAdvice, PermissionRisk
from core.linux_advisor.permission_analyzer import PermissionAnalyzer
from core.linux_advisor.permission_parser import parse_ls_line
from core.linux_advisor.risk_assessment import RiskAssessmentEngine
from core.logging import get_logger

_logger = get_logger(__name__)

#: Same `ls -l` permission-string prefix
#: `core.parsers.linux_command_parser` uses for `sniff()` — duplicated here
#: (rather than imported) since `core/linux_advisor` must never import
#: `core/parsers` sideways for anything beyond the documented model-reuse
#: exception (docs/dependency-rules.md rule 5); this is a tiny, stable regex,
#: not a shared model.
_LS_PERMISSION_PREFIX = re.compile(r"^[bcdlpsD-][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]")

#: Strips ASCII control characters (including embedded CR/LF) from a line
#: before it is logged or surfaced in advice text — the log-injection /
#: terminal-escape-injection guard (constitution §10).
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_text(text: str) -> str:
    """Removes control characters and collapses embedded newlines/carriage
    returns to a single space, so untrusted evidence content can never
    inject a fake log line or terminal escape sequence into this package's
    own output."""
    collapsed = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _CONTROL_CHAR_PATTERN.sub("", collapsed)


class LinuxSecurityAdvisoryEngine:
    def __init__(
        self,
        *,
        max_lines: int,
        max_total_chars: int,
        command_analyzer: CommandAnalyzer | None = None,
        permission_analyzer: PermissionAnalyzer | None = None,
        hardening_advisor: HardeningAdvisor | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        metrics: LinuxAdvisorMetricsCollector | None = None,
    ) -> None:
        self._max_lines = max_lines
        self._max_total_chars = max_total_chars
        self._command_analyzer = command_analyzer or CommandAnalyzer()
        self._permission_analyzer = permission_analyzer or PermissionAnalyzer()
        self._hardening_advisor = hardening_advisor or HardeningAdvisor()
        self._risk_engine = risk_engine or RiskAssessmentEngine()
        self._metrics = metrics or LinuxAdvisorMetricsCollector()

    def analyze(self, lines: list[str]) -> LinuxSecurityAdvice:
        non_blank = [line for line in lines if line.strip()]
        if len(non_blank) > self._max_lines or sum(len(line) for line in non_blank) > (
            self._max_total_chars
        ):
            raise OversizedLinuxAdvisorInputError(
                "Linux advisor input exceeds the configured maximum "
                f"({self._max_lines} lines / {self._max_total_chars} characters).",
                details={"line_count": len(non_blank), "max_lines": self._max_lines},
            )

        command_risks: list[CommandRisk] = []
        permission_risks: list[PermissionRisk] = []
        skipped = 0

        for raw_line in non_blank:
            sanitized = sanitize_text(raw_line)
            stripped = sanitized.strip()
            if not stripped:
                skipped += 1
                continue
            try:
                if _LS_PERMISSION_PREFIX.match(stripped):
                    permission = parse_ls_line(stripped)
                    permission_risks.append(self._permission_analyzer.analyze(permission))
                    self._metrics.record_permission_analyzed()
                else:
                    risk = self._command_analyzer.analyze(stripped)
                    command_risks.append(risk)
                    self._metrics.record_command_analyzed()
                    for rule_id in risk.matched_rule_ids:
                        self._metrics.record_rule_match(rule_id)
            except InvalidPermissionStringError as exc:
                skipped += 1
                self._metrics.record_failure()
                _logger.warning("linux_advisor_line_skipped", reason=str(exc))
                continue

        hardening_recommendations = self._hardening_advisor.advise(
            command_risks=command_risks, permission_risks=permission_risks
        )
        overall_risk_level, overall_confidence, overall_explanation, _dimensions = (
            self._risk_engine.assess(command_risks=command_risks, permission_risks=permission_risks)
        )

        return LinuxSecurityAdvice(
            analyzed_commands=tuple(command_risks),
            permission_analyses=tuple(permission_risks),
            hardening_recommendations=tuple(hardening_recommendations),
            overall_risk_level=overall_risk_level,
            overall_confidence=overall_confidence,
            overall_explanation=overall_explanation,
            skipped_line_count=skipped,
            total_line_count=len(non_blank),
        )
