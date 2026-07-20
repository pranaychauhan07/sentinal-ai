"""Unit tests for core/owasp_security/finding_generator.py."""

from __future__ import annotations

import pytest

from core.owasp_security.finding_generator import FindingGenerator
from core.owasp_security.models import OwaspCategory, SourceFinding, VulnerabilityCategory

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> SourceFinding:
    defaults: dict[str, object] = {
        "file_path": "app.py",
        "line_number": 10,
        "category": VulnerabilityCategory.SQL_INJECTION,
        "owasp_category": OwaspCategory.A03_INJECTION,
        "cwe_id": "CWE-89",
        "severity": "high",
        "confidence": 0.8,
        "code_snippet": "cursor.execute(query)",
        "explanation": "e",
        "recommendation": "use parameterized queries",
        "is_ast_based": True,
    }
    defaults.update(overrides)
    return SourceFinding(**defaults)  # type: ignore[arg-type]


def test_generate_normalizes_ast_based_finding() -> None:
    sast_findings = FindingGenerator().generate([_finding()])
    assert len(sast_findings) == 1
    result = sast_findings[0]
    assert result.category == VulnerabilityCategory.SQL_INJECTION
    assert result.owasp_category == OwaspCategory.A03_INJECTION
    assert result.cwe_id == "CWE-89"
    assert result.confidence == 0.8
    assert result.evidence_reference == "app.py:10: cursor.execute(query)"
    assert result.recommended_remediation == "use parameterized queries"
    assert result.source == "python_ast_analyzer"


def test_generate_discounts_pattern_based_finding() -> None:
    sast_findings = FindingGenerator().generate([_finding(is_ast_based=False)])
    assert sast_findings[0].confidence < 0.8
    assert sast_findings[0].source == "pattern_analyzer"


def test_generate_uses_default_remediation_when_none() -> None:
    sast_findings = FindingGenerator().generate([_finding(recommendation=None)])
    assert sast_findings[0].recommended_remediation
