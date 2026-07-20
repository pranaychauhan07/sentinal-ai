"""Unit tests for core/tools/web_security_tools.py."""

from __future__ import annotations

import pytest

from core.tools.web_security_tools import (
    OwaspFindingSummaryInput,
    WebSecurityAdvisoryInput,
    WebSecurityAdvisoryTool,
)

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> OwaspFindingSummaryInput:
    defaults: dict[str, object] = {
        "category": "a05_security_misconfiguration",
        "severity": "medium",
        "confidence": 0.8,
        "explanation": "e",
        "evidence_reference": "x",
        "recommended_remediation": "r",
        "source": "header_analyzer",
    }
    defaults.update(overrides)
    return OwaspFindingSummaryInput(**defaults)  # type: ignore[arg-type]


def test_empty_input_returns_zeroed_output() -> None:
    result = WebSecurityAdvisoryTool()(WebSecurityAdvisoryInput())
    assert result.finding_count == 0
    assert result.category_counts == {}
    assert result.severity_counts == {}


def test_counts_by_category_and_severity() -> None:
    findings = [
        _finding(category="a05_security_misconfiguration", severity="medium"),
        _finding(category="a02_cryptographic_failures", severity="high"),
    ]
    result = WebSecurityAdvisoryTool()(WebSecurityAdvisoryInput(findings=findings))
    assert result.finding_count == 2
    assert result.category_counts == {
        "a05_security_misconfiguration": 1,
        "a02_cryptographic_failures": 1,
    }
    assert result.severity_counts == {"medium": 1, "high": 1}


def test_top_findings_ranked_by_severity() -> None:
    findings = [
        _finding(source="low", severity="low"),
        _finding(source="critical", severity="critical"),
    ]
    result = WebSecurityAdvisoryTool()(WebSecurityAdvisoryInput(findings=findings, top_n=1))
    assert len(result.top_findings) == 1
    assert result.top_findings[0].source == "critical"


def test_overall_verdict_passed_through_unchanged() -> None:
    result = WebSecurityAdvisoryTool()(
        WebSecurityAdvisoryInput(
            overall_risk_level="high", overall_confidence=0.7, overall_explanation="x"
        )
    )
    assert result.overall_risk_level == "high"
    assert result.overall_confidence == 0.7
    assert result.overall_explanation == "x"


def test_deterministic() -> None:
    tool = WebSecurityAdvisoryTool()
    arguments = WebSecurityAdvisoryInput(findings=[_finding()])
    assert tool(arguments) == tool(arguments)
