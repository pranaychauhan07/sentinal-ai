"""``HeaderAnalyzer`` — analyzes a set of already-parsed HTTP headers for
missing security headers (`header_rules.MISSING_HEADER_SPECS`) and
value-quality issues (`header_rules.DEFAULT_HEADER_VALUE_RULES`, evaluated
via `rule_engine.RuleEngine`). `severity=INFO` with no matched issue is a
real, reachable "well-configured header" outcome.
"""

from __future__ import annotations

from core.owasp_web.header_rules import DEFAULT_HEADER_VALUE_RULES, MISSING_HEADER_SPECS
from core.owasp_web.models import HeaderFinding, severity_rank
from core.owasp_web.rule_engine import RuleEngine


class HeaderAnalyzer:
    def __init__(self, *, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine(list(DEFAULT_HEADER_VALUE_RULES))

    def analyze_missing(self, headers: dict[str, str]) -> list[HeaderFinding]:
        """Checks the task brief's six named security headers for outright
        absence — case-insensitive lookup against `headers`."""
        present_lower = {name.lower() for name in headers}
        findings: list[HeaderFinding] = []
        for spec in MISSING_HEADER_SPECS:
            if spec.header_name.lower() in present_lower:
                continue
            findings.append(
                HeaderFinding(
                    header_name=spec.header_name,
                    raw_text="",
                    category=spec.category,
                    severity=spec.severity,
                    confidence=1.0,
                    explanation=spec.explanation,
                    recommendation=spec.recommendation,
                    matched_rule_ids=(f"missing_{spec.header_name.lower().replace('-', '_')}",),
                )
            )
        return findings

    def analyze_header(self, name: str, value: str, *, raw_text: str) -> HeaderFinding | None:
        """Runs value-quality rules against one present header. Returns
        `None` (a well-configured header) when nothing matches."""
        matches = self._rule_engine.evaluate(f"{name}: {value}")
        if not matches:
            return None
        highest = max(matches, key=lambda m: severity_rank(m.severity))
        return HeaderFinding(
            header_name=name,
            raw_text=raw_text,
            category=highest.category,
            severity=highest.severity,
            confidence=highest.confidence,
            explanation=highest.explanation,
            recommendation=highest.recommendation,
            matched_rule_ids=tuple(m.rule_id for m in matches),
        )

    def analyze(self, headers: dict[str, tuple[str, str]]) -> list[HeaderFinding]:
        """`headers`: `{lowercased_name: (original_name, value)}`. Returns
        missing-header findings plus one finding per header with a matched
        value-quality issue (well-configured headers are silently omitted —
        `WebSecurityAdvisoryEngine` tracks `total_line_count` separately)."""
        findings = self.analyze_missing({name: value for name, (_, value) in headers.items()})
        for _lower_name, (original_name, value) in headers.items():
            finding = self.analyze_header(
                original_name, value, raw_text=f"{original_name}: {value}"
            )
            if finding is not None:
                findings.append(finding)
        return findings
