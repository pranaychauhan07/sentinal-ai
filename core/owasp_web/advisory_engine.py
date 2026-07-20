"""``WebSecurityAdvisoryEngine`` — the orchestrator. Takes the parser's raw
per-line text (`core.parsers.http_transaction_parser.HttpTransactionParser`'s
`EvidenceRecord.raw_line` values), classifies each line (a `Set-Cookie` line
-> `cookie_analyzer.py`; a line containing a JWT-shaped token ->
`jwt_analyzer.py`; a generic `Name: Value` header line -> collected for
`header_analyzer.py`; everything else -> `misconfiguration_detector.py`),
normalizes every analyzer's finding into `finding_generator.py`'s unified
`OwaspFinding` shape, runs `risk_assessment.py` over the accumulated
findings, and returns the final `WebSecurityAdvice`.

Defends against three failure classes without ever aborting the whole
artifact (constitution §1.7):

1. **Oversized input** — a configurable max-line/max-character guard raises
   `OversizedWebSecurityInputError` before any per-line work starts.
2. **Malformed individual lines** — an unparseable `Set-Cookie` line or a
   structurally invalid JWT is skipped (counted in `skipped_line_count`),
   never aborts the rest.
3. **Log-injection-shaped content** — every line is sanitized (control
   characters and embedded newlines stripped) before it ever appears in a
   log line or in the advice text itself. This package performs pure text
   analysis and never sends a live HTTP request, executes, or `eval`s any
   analyzed content (constitution §10).
"""

from __future__ import annotations

import re

from core.logging import get_logger
from core.owasp_web.cookie_analyzer import CookieAnalyzer, parse_set_cookie_line
from core.owasp_web.exceptions import (
    MalformedHttpLineError,
    MalformedJwtError,
    OversizedWebSecurityInputError,
)
from core.owasp_web.finding_generator import FindingGenerator
from core.owasp_web.header_analyzer import HeaderAnalyzer
from core.owasp_web.jwt_analyzer import JwtAnalyzer, parse_jwt
from core.owasp_web.metrics import WebSecurityMetricsCollector
from core.owasp_web.misconfiguration_detector import MisconfigurationDetector
from core.owasp_web.models import (
    CookieFinding,
    HeaderFinding,
    JwtFinding,
    MisconfigurationFinding,
    WebSecurityAdvice,
)
from core.owasp_web.risk_assessment import RiskAssessmentEngine

_logger = get_logger(__name__)

#: A JWT-shaped token: three dot-separated base64url segments, each long
#: enough to exclude short numeric version strings (e.g. "1.2.3") from
#: matching. Not a validation of the token's contents — `jwt_analyzer.py`
#: does the actual structural decode.
_JWT_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
)

#: A `Set-Cookie` header line.
_SET_COOKIE_LINE_PATTERN = re.compile(r"^set-cookie\s*:", re.IGNORECASE)

#: A generic `Name: Value` HTTP header line.
_HEADER_LINE_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s?(.*)$")

#: Strips ASCII control characters (including embedded CR/LF) from a line
#: before it is logged or surfaced in advice text — the log-injection guard
#: (constitution §10), identical to `core.linux_advisor.advisory_engine`'s.
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_text(text: str) -> str:
    """Removes control characters and collapses embedded newlines/carriage
    returns to a single space, so untrusted evidence content can never
    inject a fake log line into this package's own output."""
    collapsed = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _CONTROL_CHAR_PATTERN.sub("", collapsed)


class WebSecurityAdvisoryEngine:
    def __init__(
        self,
        *,
        max_lines: int,
        max_total_chars: int,
        header_analyzer: HeaderAnalyzer | None = None,
        cookie_analyzer: CookieAnalyzer | None = None,
        jwt_analyzer: JwtAnalyzer | None = None,
        misconfiguration_detector: MisconfigurationDetector | None = None,
        finding_generator: FindingGenerator | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        metrics: WebSecurityMetricsCollector | None = None,
    ) -> None:
        self._max_lines = max_lines
        self._max_total_chars = max_total_chars
        self._header_analyzer = header_analyzer or HeaderAnalyzer()
        self._cookie_analyzer = cookie_analyzer or CookieAnalyzer()
        self._jwt_analyzer = jwt_analyzer or JwtAnalyzer()
        self._misconfiguration_detector = misconfiguration_detector or MisconfigurationDetector()
        self._finding_generator = finding_generator or FindingGenerator()
        self._risk_engine = risk_engine or RiskAssessmentEngine()
        self._metrics = metrics or WebSecurityMetricsCollector()

    def analyze(self, lines: list[str]) -> WebSecurityAdvice:
        non_blank = [line for line in lines if line.strip()]
        if len(non_blank) > self._max_lines or sum(len(line) for line in non_blank) > (
            self._max_total_chars
        ):
            raise OversizedWebSecurityInputError(
                "Web security input exceeds the configured maximum "
                f"({self._max_lines} lines / {self._max_total_chars} characters).",
                details={"line_count": len(non_blank), "max_lines": self._max_lines},
            )

        header_lines: dict[str, tuple[str, str]] = {}
        cookie_findings: list[CookieFinding] = []
        jwt_findings: list[JwtFinding] = []
        misconfiguration_findings: list[MisconfigurationFinding] = []
        skipped = 0

        for raw_line in non_blank:
            sanitized = sanitize_text(raw_line)
            stripped = sanitized.strip()
            if not stripped:
                skipped += 1
                continue

            jwt_match = _JWT_TOKEN_PATTERN.search(stripped)
            if jwt_match:
                try:
                    jwt = parse_jwt(jwt_match.group(0))
                except MalformedJwtError as exc:
                    skipped += 1
                    self._metrics.record_failure()
                    _logger.warning("web_security_line_skipped", reason=str(exc))
                    continue
                self._metrics.record_jwt_analyzed()
                jwt_finding = self._jwt_analyzer.analyze(jwt)
                if jwt_finding is not None:
                    jwt_findings.append(jwt_finding)
                continue

            if _SET_COOKIE_LINE_PATTERN.match(stripped):
                try:
                    cookie = parse_set_cookie_line(stripped)
                except MalformedHttpLineError as exc:
                    skipped += 1
                    self._metrics.record_failure()
                    _logger.warning("web_security_line_skipped", reason=str(exc))
                    continue
                self._metrics.record_cookie_analyzed()
                cookie_finding = self._cookie_analyzer.analyze(cookie)
                if cookie_finding is not None:
                    cookie_findings.append(cookie_finding)
                continue

            header_match = _HEADER_LINE_PATTERN.match(stripped)
            if header_match:
                name, value = header_match.group(1), header_match.group(2)
                header_lines[name.lower()] = (name, value)
                self._metrics.record_header_analyzed()
                continue

            self._metrics.record_misconfiguration_candidate_analyzed()
            misconfig_finding = self._misconfiguration_detector.analyze(stripped)
            if misconfig_finding is not None:
                misconfiguration_findings.append(misconfig_finding)

        # Missing-header presence checks only make sense when the artifact
        # actually contains evidence to judge — an entirely empty artifact
        # (or one reduced to nothing after sanitization) must never be
        # reported as "6 headers missing", which would conflate "no
        # evidence" with "insecure configuration" (constitution §1.7's
        # "insufficient evidence" vs. "clean bill" distinction, applied here).
        header_findings: list[HeaderFinding] = (
            self._header_analyzer.analyze(header_lines) if non_blank else []
        )
        for finding in header_findings:
            for rule_id in finding.matched_rule_ids:
                self._metrics.record_rule_match(rule_id)

        owasp_findings = self._finding_generator.generate(
            header_findings=header_findings,
            cookie_findings=cookie_findings,
            jwt_findings=jwt_findings,
            misconfiguration_findings=misconfiguration_findings,
        )
        overall_risk_level, overall_confidence, overall_explanation, _dimensions = (
            self._risk_engine.assess(
                findings=owasp_findings, distinct_sources={f.source for f in owasp_findings}
            )
        )

        return WebSecurityAdvice(
            header_findings=tuple(header_findings),
            cookie_findings=tuple(cookie_findings),
            jwt_findings=tuple(jwt_findings),
            misconfiguration_findings=tuple(misconfiguration_findings),
            owasp_findings=tuple(owasp_findings),
            overall_risk_level=overall_risk_level,
            overall_confidence=overall_confidence,
            overall_explanation=overall_explanation,
            skipped_line_count=skipped,
            total_line_count=len(non_blank),
        )
