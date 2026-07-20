"""Unit tests for core/owasp_web/cookie_analyzer.py, including
`parse_set_cookie_line`."""

from __future__ import annotations

import pytest

from core.owasp_web.cookie_analyzer import CookieAnalyzer, parse_set_cookie_line
from core.owasp_web.exceptions import MalformedHttpLineError
from core.owasp_web.models import OwaspCategory, ParsedCookie, WebSecuritySeverity

pytestmark = pytest.mark.unit


def test_parse_well_formed_cookie_line() -> None:
    cookie = parse_set_cookie_line(
        "Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax; Max-Age=3600; Path=/"
    )
    assert cookie.name == "session"
    assert cookie.value == "abc123"
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "Lax"
    assert cookie.max_age_seconds == 3600
    assert cookie.path == "/"


def test_parse_cookie_line_without_name_value_raises() -> None:
    with pytest.raises(MalformedHttpLineError):
        parse_set_cookie_line("Set-Cookie: ; Secure")


def test_well_configured_cookie_has_no_finding() -> None:
    cookie = parse_set_cookie_line("Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict")
    assert CookieAnalyzer().analyze(cookie) is None


def test_missing_secure_flagged() -> None:
    cookie = parse_set_cookie_line("Set-Cookie: session=abc; HttpOnly; SameSite=Strict")
    finding = CookieAnalyzer().analyze(cookie)
    assert finding is not None
    assert "cookie_missing_secure" in finding.matched_issue_ids
    assert finding.category == OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES


def test_session_like_name_raises_severity() -> None:
    cookie = parse_set_cookie_line("Set-Cookie: authtoken=abc; HttpOnly; SameSite=Strict")
    finding = CookieAnalyzer().analyze(cookie)
    assert finding is not None
    assert finding.severity == WebSecuritySeverity.HIGH


def test_samesite_none_without_secure_flagged() -> None:
    cookie = parse_set_cookie_line("Set-Cookie: session=abc; HttpOnly; SameSite=None")
    finding = CookieAnalyzer().analyze(cookie)
    assert finding is not None
    assert "cookie_samesite_none_without_secure" in finding.matched_issue_ids


def test_excessive_expiration_flagged() -> None:
    cookie = ParsedCookie(
        raw_text="x",
        name="session",
        secure=True,
        http_only=True,
        same_site="Strict",
        has_expiration=True,
        max_age_seconds=100_000_000,
    )
    finding = CookieAnalyzer().analyze(cookie)
    assert finding is not None
    assert "cookie_excessive_expiration" in finding.matched_issue_ids


def test_broad_domain_flagged() -> None:
    cookie = ParsedCookie(
        raw_text="x",
        name="session",
        secure=True,
        http_only=True,
        same_site="Strict",
        domain=".example.com",
    )
    finding = CookieAnalyzer().analyze(cookie)
    assert finding is not None
    assert "cookie_broad_domain" in finding.matched_issue_ids
