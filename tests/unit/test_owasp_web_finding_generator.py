"""Unit tests for core/owasp_web/finding_generator.py."""

from __future__ import annotations

import pytest

from core.owasp_web.finding_generator import FindingGenerator
from core.owasp_web.models import (
    CookieFinding,
    HeaderFinding,
    JwtFinding,
    MisconfigurationFinding,
    OwaspCategory,
    ParsedCookie,
    ParsedJwt,
    WebSecuritySeverity,
)

pytestmark = pytest.mark.unit


def test_from_header_finding_normalizes_shape() -> None:
    header_finding = HeaderFinding(
        header_name="Strict-Transport-Security",
        raw_text="",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=1.0,
        explanation="missing hsts",
        recommendation="add hsts",
    )
    owasp_finding = FindingGenerator().from_header_finding(header_finding)
    assert owasp_finding.category == OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES
    assert owasp_finding.source == "header_analyzer"
    assert owasp_finding.evidence_reference == "Strict-Transport-Security"
    assert owasp_finding.recommended_remediation == "add hsts"


def test_from_cookie_finding_uses_raw_text_reference() -> None:
    cookie = ParsedCookie(raw_text="Set-Cookie: session=abc", name="session")
    cookie_finding = CookieFinding(
        cookie=cookie,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.HIGH,
        confidence=0.9,
        explanation="missing secure",
    )
    owasp_finding = FindingGenerator().from_cookie_finding(cookie_finding)
    assert owasp_finding.evidence_reference == "Set-Cookie: session=abc"
    assert owasp_finding.recommended_remediation  # default remediation applied
    assert owasp_finding.source == "cookie_analyzer"


def test_from_jwt_finding() -> None:
    jwt = ParsedJwt(raw_text="header.payload.sig", alg="none")
    jwt_finding = JwtFinding(
        jwt=jwt,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.CRITICAL,
        confidence=0.9,
        explanation="alg none",
        recommendation="reject",
    )
    owasp_finding = FindingGenerator().from_jwt_finding(jwt_finding)
    assert owasp_finding.evidence_reference == "header.payload.sig"
    assert owasp_finding.recommended_remediation == "reject"


def test_from_misconfiguration_finding() -> None:
    misconfig_finding = MisconfigurationFinding(
        raw_text="Index of /backups",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=0.9,
        explanation="dir listing",
        recommendation="disable listing",
    )
    owasp_finding = FindingGenerator().from_misconfiguration_finding(misconfig_finding)
    assert owasp_finding.source == "misconfiguration_detector"
    assert owasp_finding.evidence_reference == "Index of /backups"


def test_generate_aggregates_all_finding_kinds() -> None:
    header_finding = HeaderFinding(
        header_name="X-Frame-Options",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=1.0,
        explanation="missing",
    )
    findings = FindingGenerator().generate(
        header_findings=[header_finding],
        cookie_findings=[],
        jwt_findings=[],
        misconfiguration_findings=[],
    )
    assert len(findings) == 1
    assert findings[0].source == "header_analyzer"
