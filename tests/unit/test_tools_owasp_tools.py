"""Unit tests for core/tools/owasp_tools.py."""

from __future__ import annotations

import pytest

from core.tools.owasp_tools import (
    OwaspSecurityAssessmentInput,
    OwaspSecurityAssessmentTool,
    SastFindingSummaryInput,
)

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> SastFindingSummaryInput:
    defaults: dict[str, object] = {
        "category": "sql_injection",
        "owasp_category": "a03_injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "confidence": 0.8,
        "explanation": "e",
        "evidence_reference": "x",
        "recommended_remediation": "r",
        "source": "python_ast_analyzer",
    }
    defaults.update(overrides)
    return SastFindingSummaryInput(**defaults)  # type: ignore[arg-type]


def test_empty_input_returns_zeroed_output() -> None:
    result = OwaspSecurityAssessmentTool()(OwaspSecurityAssessmentInput())
    assert result.finding_count == 0
    assert result.category_counts == {}
    assert result.cwe_counts == {}


def test_counts_by_category_cwe_and_severity() -> None:
    findings = [
        _finding(category="sql_injection", cwe_id="CWE-89", severity="high"),
        _finding(category="command_injection", cwe_id="CWE-78", severity="critical"),
    ]
    result = OwaspSecurityAssessmentTool()(OwaspSecurityAssessmentInput(findings=findings))
    assert result.finding_count == 2
    assert result.category_counts == {"sql_injection": 1, "command_injection": 1}
    assert result.cwe_counts == {"CWE-89": 1, "CWE-78": 1}
    assert result.severity_counts == {"high": 1, "critical": 1}


def test_top_findings_ranked_by_severity() -> None:
    findings = [
        _finding(source="low", severity="low"),
        _finding(source="critical", severity="critical"),
    ]
    result = OwaspSecurityAssessmentTool()(OwaspSecurityAssessmentInput(findings=findings, top_n=1))
    assert len(result.top_findings) == 1
    assert result.top_findings[0].source == "critical"


def test_overall_verdict_and_language_passed_through_unchanged() -> None:
    result = OwaspSecurityAssessmentTool()(
        OwaspSecurityAssessmentInput(
            language="python",
            overall_risk_level="high",
            overall_confidence=0.7,
            overall_explanation="x",
            parse_degraded=True,
        )
    )
    assert result.language == "python"
    assert result.overall_risk_level == "high"
    assert result.overall_confidence == 0.7
    assert result.parse_degraded is True


def test_deterministic() -> None:
    tool = OwaspSecurityAssessmentTool()
    arguments = OwaspSecurityAssessmentInput(findings=[_finding()])
    assert tool(arguments) == tool(arguments)
