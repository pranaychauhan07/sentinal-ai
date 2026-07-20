"""Unit tests for core/owasp_web/jwt_analyzer.py, including `parse_jwt`."""

from __future__ import annotations

import base64
import json
import time

import pytest

from core.owasp_web.exceptions import MalformedJwtError
from core.owasp_web.jwt_analyzer import JwtAnalyzer, parse_jwt
from core.owasp_web.models import OwaspCategory

pytestmark = pytest.mark.unit


def _b64u(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _jwt(header: dict[str, object], payload: dict[str, object], signature: str = "sig") -> str:
    return f"{_b64u(header)}.{_b64u(payload)}.{signature}"


def test_parse_well_formed_jwt() -> None:
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": int(time.time()) + 3600})
    parsed = parse_jwt(token)
    assert parsed.alg == "HS256"
    assert parsed.is_expired is False


def test_parse_malformed_jwt_wrong_segment_count_raises() -> None:
    with pytest.raises(MalformedJwtError):
        parse_jwt("not.a.valid.jwt.token")


def test_parse_malformed_jwt_bad_base64_raises() -> None:
    with pytest.raises(MalformedJwtError):
        parse_jwt("###.###.###")


def test_alg_none_is_critical() -> None:
    token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
    parsed = parse_jwt(token)
    finding = JwtAnalyzer().analyze(parsed)
    assert finding is not None
    assert "jwt_none_or_missing_algorithm" in finding.matched_issue_ids
    assert finding.category == OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES


def test_missing_expiration_flagged() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1", "iss": "auth", "aud": "api"})
    parsed = parse_jwt(token)
    finding = JwtAnalyzer().analyze(parsed)
    assert finding is not None
    assert "jwt_missing_expiration" in finding.matched_issue_ids


def test_expired_token_flagged_as_info() -> None:
    token = _jwt(
        {"alg": "HS256"},
        {"sub": "1", "iss": "auth", "aud": "api", "exp": int(time.time()) - 3600},
    )
    parsed = parse_jwt(token)
    finding = JwtAnalyzer().analyze(parsed)
    assert finding is not None
    assert "jwt_expired" in finding.matched_issue_ids


def test_missing_issuer_and_audience_flagged() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1", "exp": int(time.time()) + 3600})
    parsed = parse_jwt(token)
    finding = JwtAnalyzer().analyze(parsed)
    assert finding is not None
    assert "jwt_missing_issuer" in finding.matched_issue_ids
    assert "jwt_missing_audience" in finding.matched_issue_ids


def test_header_anomaly_jku_flagged() -> None:
    token = _jwt(
        {"alg": "HS256", "jku": "https://attacker.example/keys.json"},
        {"sub": "1", "iss": "auth", "aud": "api", "exp": int(time.time()) + 3600},
    )
    parsed = parse_jwt(token)
    finding = JwtAnalyzer().analyze(parsed)
    assert finding is not None
    assert "jwt_header_anomaly" in finding.matched_issue_ids


def test_fully_well_formed_jwt_has_no_finding() -> None:
    token = _jwt(
        {"alg": "HS256"},
        {"sub": "1", "iss": "auth", "aud": "api", "exp": int(time.time()) + 3600},
    )
    parsed = parse_jwt(token)
    assert JwtAnalyzer().analyze(parsed) is None
