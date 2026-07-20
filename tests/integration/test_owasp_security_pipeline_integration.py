"""Integration test for core/services/owasp_security_service.py — exercises
the real `SourceCodeParser` and the real `SourceCodeAnalysisEngine` together
against `data/sample_evidence/vulnerable_app.py` (command injection,
hardcoded secret, SQL injection, weak cryptography, insecure randomness,
unsafe deserialization, path traversal, broken authentication, open
redirect, sensitive information exposure, insecure configuration), proving
detection end-to-end. No database fixture is needed — this framework never
persists (ADR-0021).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import get_settings
from core.owasp_security.models import SastSeverity, SourceLanguage, VulnerabilityCategory
from core.parsers.base import RawEvidenceInput
from core.parsers.source_code_parser import SourceCodeParser
from core.services.owasp_security_service import assess_source_code

pytestmark = pytest.mark.integration

_VULNERABLE_APP = Path("data/sample_evidence/vulnerable_app.py")
_VULNERABLE_APP_JS = Path("data/sample_evidence/vulnerable_app.js")
_VULNERABLE_APP_JAVA = Path("data/sample_evidence/VulnerableApp.java")
_SAFE_APP = Path("data/sample_evidence/safe_app.py")


def test_full_pipeline_from_real_evidence_fixture() -> None:
    parser = SourceCodeParser()
    raw = RawEvidenceInput(filename="vulnerable_app.py", content=_VULNERABLE_APP.read_bytes())
    normalized_evidence = parser(raw)
    assert normalized_evidence.record_count == 1

    result = assess_source_code(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    assert advice.language == SourceLanguage.PYTHON
    assert advice.parse_degraded is False

    categories = {f.category for f in advice.sast_findings}
    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.HARDCODED_SECRETS in categories
    assert VulnerabilityCategory.SQL_INJECTION in categories
    assert VulnerabilityCategory.WEAK_CRYPTOGRAPHY in categories
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in categories
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in categories
    assert VulnerabilityCategory.PATH_TRAVERSAL in categories
    assert VulnerabilityCategory.BROKEN_AUTHENTICATION in categories
    assert VulnerabilityCategory.OPEN_REDIRECT in categories
    assert VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE in categories
    assert VulnerabilityCategory.INSECURE_CONFIGURATION in categories

    # Every finding is genuinely AST-based for a Python file.
    assert all(f.source == "python_ast_analyzer" for f in advice.sast_findings)
    # Every finding carries a real OWASP category and CWE id.
    assert all(f.owasp_category is not None for f in advice.sast_findings)
    assert all(f.cwe_id.startswith("CWE-") for f in advice.sast_findings)

    # Secure-coding recommendations cover baseline + finding-triggered.
    assert any(r.is_baseline for r in advice.secure_coding_recommendations)
    assert any(not r.is_baseline for r in advice.secure_coding_recommendations)

    assert advice.overall_risk_level in (SastSeverity.HIGH, SastSeverity.CRITICAL)


def test_javascript_fixture_detected_via_pattern_analysis() -> None:
    """Per-language coverage: JavaScript, pattern-based (no AST library for
    this language, docs/adr/0021)."""
    parser = SourceCodeParser()
    raw = RawEvidenceInput(filename="vulnerable_app.js", content=_VULNERABLE_APP_JS.read_bytes())
    normalized_evidence = parser(raw)

    result = assess_source_code(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    assert advice.language == SourceLanguage.JAVASCRIPT
    categories = {f.category for f in advice.sast_findings}
    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.XSS in categories
    assert VulnerabilityCategory.HARDCODED_SECRETS in categories
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in categories
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in categories
    assert all(f.source == "pattern_analyzer" for f in advice.sast_findings)
    # Pattern-based findings are confidence-discounted relative to AST ones.
    assert all(f.confidence < 1.0 for f in advice.sast_findings)


def test_java_fixture_detected_via_pattern_analysis() -> None:
    """Per-language coverage: Java, pattern-based (no AST library for this
    language, docs/adr/0021)."""
    parser = SourceCodeParser()
    raw = RawEvidenceInput(filename="VulnerableApp.java", content=_VULNERABLE_APP_JAVA.read_bytes())
    normalized_evidence = parser(raw)

    result = assess_source_code(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    assert advice.language == SourceLanguage.JAVA
    categories = {f.category for f in advice.sast_findings}
    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.WEAK_CRYPTOGRAPHY in categories
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in categories
    assert all(f.source == "pattern_analyzer" for f in advice.sast_findings)


def test_false_positive_reduction_clean_python_file_yields_no_findings() -> None:
    """False-positive-reduction test: ordinary, non-vulnerable Python code
    (SHA-256 for a cache key, `secrets.token_urlsafe` for a session token, a
    constant-path `open()`) must not trigger any finding."""
    parser = SourceCodeParser()
    raw = RawEvidenceInput(filename="safe_app.py", content=_SAFE_APP.read_bytes())
    normalized_evidence = parser(raw)

    result = assess_source_code(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    assert advice.sast_findings == ()
    assert advice.overall_risk_level == SastSeverity.INFO
    assert advice.parse_degraded is False
