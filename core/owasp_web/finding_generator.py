"""``FindingGenerator`` — the task brief's "Finding Generator" capability:
the single place every analyzer's narrower finding type (`HeaderFinding`,
`CookieFinding`, `JwtFinding`, `MisconfigurationFinding`) is normalized into
the unified `OwaspFinding` shape (OWASP category, severity, confidence,
evidence reference, explanation, recommended remediation). Analyzers detect;
this module normalizes into the one reportable shape (Single Responsibility
Principle applied at the module level, constitution §1.4).
"""

from __future__ import annotations

from core.owasp_web.models import (
    CookieFinding,
    HeaderFinding,
    JwtFinding,
    MisconfigurationFinding,
    OwaspFinding,
)

_DEFAULT_REMEDIATION = "Review and remediate per the finding's explanation."


class FindingGenerator:
    def from_header_finding(self, finding: HeaderFinding) -> OwaspFinding:
        return OwaspFinding(
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence_reference=finding.raw_text or finding.header_name,
            explanation=finding.explanation,
            recommended_remediation=finding.recommendation or _DEFAULT_REMEDIATION,
            source="header_analyzer",
        )

    def from_cookie_finding(self, finding: CookieFinding) -> OwaspFinding:
        return OwaspFinding(
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence_reference=finding.cookie.raw_text or finding.cookie.name,
            explanation=finding.explanation,
            recommended_remediation=finding.recommendation or _DEFAULT_REMEDIATION,
            source="cookie_analyzer",
        )

    def from_jwt_finding(self, finding: JwtFinding) -> OwaspFinding:
        return OwaspFinding(
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence_reference=finding.jwt.raw_text,
            explanation=finding.explanation,
            recommended_remediation=finding.recommendation or _DEFAULT_REMEDIATION,
            source="jwt_analyzer",
        )

    def from_misconfiguration_finding(self, finding: MisconfigurationFinding) -> OwaspFinding:
        return OwaspFinding(
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence_reference=finding.raw_text,
            explanation=finding.explanation,
            recommended_remediation=finding.recommendation or _DEFAULT_REMEDIATION,
            source="misconfiguration_detector",
        )

    def generate(
        self,
        *,
        header_findings: list[HeaderFinding],
        cookie_findings: list[CookieFinding],
        jwt_findings: list[JwtFinding],
        misconfiguration_findings: list[MisconfigurationFinding],
    ) -> list[OwaspFinding]:
        findings: list[OwaspFinding] = []
        findings.extend(self.from_header_finding(f) for f in header_findings)
        findings.extend(self.from_cookie_finding(f) for f in cookie_findings)
        findings.extend(self.from_jwt_finding(f) for f in jwt_findings)
        findings.extend(self.from_misconfiguration_finding(f) for f in misconfiguration_findings)
        return findings
