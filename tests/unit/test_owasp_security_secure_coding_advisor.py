"""Unit tests for core/owasp_security/secure_coding_advisor.py."""

from __future__ import annotations

import pytest

from core.owasp_security.models import OwaspCategory, SourceFinding, VulnerabilityCategory
from core.owasp_security.secure_coding_advisor import SecureCodingAdvisor

pytestmark = pytest.mark.unit


def test_baseline_recommendations_cover_all_categories() -> None:
    recommendations = SecureCodingAdvisor().advise([])
    baseline = [r for r in recommendations if r.is_baseline]
    assert {r.category for r in baseline} == set(VulnerabilityCategory)


def test_finding_triggered_recommendation_names_the_subject() -> None:
    finding = SourceFinding(
        file_path="app.py",
        line_number=12,
        category=VulnerabilityCategory.SQL_INJECTION,
        owasp_category=OwaspCategory.A03_INJECTION,
        cwe_id="CWE-89",
        severity="high",
        confidence=0.75,
        explanation="dynamic query",
        recommendation="use parameterized queries",
    )
    recommendations = SecureCodingAdvisor().advise([finding])
    triggered = [r for r in recommendations if not r.is_baseline]
    assert len(triggered) == 1
    assert triggered[0].related_subject == "app.py:12"
    assert triggered[0].recommendation == "use parameterized queries"


def test_finding_without_recommendation_is_skipped() -> None:
    finding = SourceFinding(
        file_path="app.py",
        category=VulnerabilityCategory.SQL_INJECTION,
        owasp_category=OwaspCategory.A03_INJECTION,
        cwe_id="CWE-89",
        severity="high",
        confidence=0.75,
        explanation="dynamic query",
        recommendation=None,
    )
    recommendations = SecureCodingAdvisor().advise([finding])
    assert all(r.is_baseline for r in recommendations)
