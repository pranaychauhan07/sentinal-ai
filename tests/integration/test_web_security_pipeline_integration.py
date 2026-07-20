"""Integration test for core/services/web_security_service.py — exercises
the real `HttpTransactionParser` and the real `WebSecurityAdvisoryEngine`
together against `data/sample_evidence/http_transaction.txt` (missing
security headers, a weak CSP, a Server version-disclosure header, two
misconfigured cookies, an unsecured `alg=none` JWT, and a directory-listing/
default-credentials/debug-endpoint line), proving detection end-to-end. No
database fixture is needed — this framework never persists (ADR-0020).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import get_settings
from core.owasp_web.models import OwaspCategory, WebSecuritySeverity
from core.parsers.base import RawEvidenceInput
from core.parsers.http_transaction_parser import HttpTransactionParser
from core.services.web_security_service import assess_http_transaction

pytestmark = pytest.mark.integration

_HTTP_TRANSACTION = Path("data/sample_evidence/http_transaction.txt")


def test_full_pipeline_from_real_evidence_fixture() -> None:
    parser = HttpTransactionParser()
    raw = RawEvidenceInput(filename="http_transaction.txt", content=_HTTP_TRANSACTION.read_bytes())
    normalized_evidence = parser(raw)
    assert normalized_evidence.record_count > 0

    result = assess_http_transaction(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    # Missing security headers flagged (HSTS/X-Frame-Options/X-Content-Type-
    # Options/Referrer-Policy/Permissions-Policy — CSP is present but weak).
    missing_names = {f.header_name for f in advice.header_findings}
    assert "Strict-Transport-Security" in missing_names
    assert "X-Frame-Options" in missing_names

    # Weak CSP value-quality issue flagged.
    csp_finding = next(
        f for f in advice.header_findings if f.header_name == "Content-Security-Policy"
    )
    assert "csp_unsafe_inline" in csp_finding.matched_rule_ids

    # Insecure cookies flagged.
    assert len(advice.cookie_findings) == 2
    session_finding = next(f for f in advice.cookie_findings if f.cookie.name == "session")
    assert "cookie_missing_secure" in session_finding.matched_issue_ids

    # Unsecured JWT (alg=none) flagged as critical.
    assert len(advice.jwt_findings) == 1
    assert advice.jwt_findings[0].severity == WebSecuritySeverity.CRITICAL
    assert advice.jwt_findings[0].category == OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES

    # Directory listing / default-credentials / debug-endpoint line flagged.
    assert len(advice.misconfiguration_findings) == 2

    # Unified OWASP findings generated for every analyzer's output.
    assert len(advice.owasp_findings) == (
        len(advice.header_findings)
        + len(advice.cookie_findings)
        + len(advice.jwt_findings)
        + len(advice.misconfiguration_findings)
    )

    assert advice.overall_risk_level == WebSecuritySeverity.CRITICAL
    assert advice.skipped_line_count == 0
