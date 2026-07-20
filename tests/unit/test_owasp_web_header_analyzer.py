"""Unit tests for core/owasp_web/header_analyzer.py."""

from __future__ import annotations

import pytest

from core.owasp_web.header_analyzer import HeaderAnalyzer
from core.owasp_web.models import OwaspCategory, WebSecuritySeverity

pytestmark = pytest.mark.unit


def test_all_six_headers_missing_produces_six_findings() -> None:
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze({})
    assert len(findings) == 6
    names = {f.header_name for f in findings}
    assert names == {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    }


def test_well_configured_headers_produce_no_findings() -> None:
    analyzer = HeaderAnalyzer()
    headers = {
        "content-security-policy": (
            "Content-Security-Policy",
            "default-src 'self'",
        ),
        "strict-transport-security": (
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        ),
        "x-frame-options": ("X-Frame-Options", "DENY"),
        "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
        "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin"),
        "permissions-policy": ("Permissions-Policy", "geolocation=()"),
    }
    findings = analyzer.analyze(headers)
    assert findings == []


def test_csp_unsafe_inline_flagged() -> None:
    analyzer = HeaderAnalyzer()
    finding = analyzer.analyze_header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'unsafe-inline'",
        raw_text="Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'",
    )
    assert finding is not None
    assert finding.category == OwaspCategory.A05_SECURITY_MISCONFIGURATION
    assert "csp_unsafe_inline" in finding.matched_rule_ids


def test_hsts_short_max_age_flagged() -> None:
    analyzer = HeaderAnalyzer()
    finding = analyzer.analyze_header(
        "Strict-Transport-Security",
        "max-age=100",
        raw_text="Strict-Transport-Security: max-age=100",
    )
    assert finding is not None
    assert finding.severity in (WebSecuritySeverity.LOW, WebSecuritySeverity.INFO)


def test_missing_header_severity_none_matches_spec() -> None:
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze_missing({})
    hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
    assert hsts.category == OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES
    assert hsts.confidence == 1.0
