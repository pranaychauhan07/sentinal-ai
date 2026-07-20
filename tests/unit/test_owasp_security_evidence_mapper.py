"""Unit tests for core/owasp_security/evidence_mapper.py."""

from __future__ import annotations

import pytest

from core.owasp_security.evidence_mapper import map_evidence_reference
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
    }
    defaults.update(overrides)
    return SourceFinding(**defaults)  # type: ignore[arg-type]


def test_reference_includes_file_line_and_snippet() -> None:
    assert map_evidence_reference(_finding()) == "app.py:10: cursor.execute(query)"


def test_reference_without_line_number() -> None:
    finding = _finding(line_number=None)
    assert map_evidence_reference(finding) == "app.py: cursor.execute(query)"


def test_reference_without_snippet() -> None:
    finding = _finding(code_snippet="")
    assert map_evidence_reference(finding) == "app.py:10"
