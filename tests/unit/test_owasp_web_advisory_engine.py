"""Unit tests for core/owasp_web/advisory_engine.py — the orchestrator,
including adversarial/malformed-input and oversized-input cases."""

from __future__ import annotations

import pytest

from core.owasp_web.advisory_engine import WebSecurityAdvisoryEngine, sanitize_text
from core.owasp_web.exceptions import OversizedWebSecurityInputError
from core.owasp_web.models import WebSecuritySeverity

pytestmark = pytest.mark.unit


def _engine(**overrides: int) -> WebSecurityAdvisoryEngine:
    defaults = {"max_lines": 1000, "max_total_chars": 100_000}
    defaults.update(overrides)
    return WebSecurityAdvisoryEngine(**defaults)  # type: ignore[arg-type]


def test_empty_input_is_info_with_no_findings() -> None:
    advice = _engine().analyze([])
    assert advice.overall_risk_level == WebSecuritySeverity.INFO
    assert advice.owasp_findings == ()
    assert advice.total_line_count == 0


def test_malformed_set_cookie_line_is_skipped_not_fatal() -> None:
    advice = _engine().analyze(["Set-Cookie: ; Secure", "X-Frame-Options: DENY"])
    assert advice.skipped_line_count == 1
    assert advice.total_line_count == 2


def test_malformed_jwt_shaped_token_is_skipped_not_fatal() -> None:
    # Three dot-separated base64url segments (JWT-shaped) whose header/
    # payload segments decode to valid base64 bytes but NOT valid JSON.
    token = "aGVsbG93b3JsZGhlbGxv.YW5vdGhlcnRleHRub3Rqc29u.fakesignature"
    advice = _engine().analyze([f"Authorization: Bearer {token}"])
    assert advice.skipped_line_count == 1


def test_oversized_line_count_rejected() -> None:
    engine = _engine(max_lines=2)
    with pytest.raises(OversizedWebSecurityInputError):
        engine.analyze(["a", "b", "c"])


def test_oversized_char_count_rejected() -> None:
    engine = _engine(max_lines=1000, max_total_chars=10)
    with pytest.raises(OversizedWebSecurityInputError):
        engine.analyze(["x" * 50])


def test_control_characters_sanitized() -> None:
    assert sanitize_text("hello\x00\x1fworld\r\nnext") == "helloworld next"


def test_missing_headers_generate_findings_end_to_end() -> None:
    advice = _engine().analyze(["GET / HTTP/1.1", "HTTP/1.1 200 OK", "Content-Type: text/html"])
    assert len(advice.header_findings) == 6
    assert advice.overall_risk_level != WebSecuritySeverity.CRITICAL


def test_directory_listing_line_produces_misconfig_finding() -> None:
    advice = _engine().analyze(["Index of /backups"])
    assert len(advice.misconfiguration_findings) == 1
