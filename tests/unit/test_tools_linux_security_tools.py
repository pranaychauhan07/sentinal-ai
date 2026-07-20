"""Unit tests for core/tools/linux_security_tools.py."""

from __future__ import annotations

import pytest

from core.tools.linux_security_tools import (
    LinuxSecurityAssessmentInput,
    LinuxSecurityAssessmentTool,
    LinuxSecurityFindingSummaryInput,
)

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> LinuxSecurityFindingSummaryInput:
    defaults: dict[str, object] = {
        "category": "brute_force",
        "subject": "203.0.113.44",
        "subject_type": "ip",
        "title": "SSH brute force",
        "severity": "high",
        "composite_score": 80.0,
        "occurrence_count": 6,
    }
    defaults.update(overrides)
    return LinuxSecurityFindingSummaryInput(**defaults)  # type: ignore[arg-type]


def test_empty_findings_returns_zeroed_summary() -> None:
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=[]))
    assert result.finding_count == 0
    assert result.category_counts == {}
    assert result.severity_counts == {}
    assert result.highest_composite_score == 0.0
    assert result.top_findings == ()


def test_counts_by_category_and_severity() -> None:
    findings = [
        _finding(category="brute_force", severity="critical"),
        _finding(category="brute_force", severity="high", subject="1.2.3.4"),
        _finding(category="root_login", severity="high", subject="5.6.7.8"),
    ]
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=findings))
    assert result.finding_count == 3
    assert result.category_counts == {"brute_force": 2, "root_login": 1}
    assert result.severity_counts == {"critical": 1, "high": 2}


def test_highest_composite_score() -> None:
    findings = [_finding(composite_score=40.0), _finding(composite_score=95.0, subject="x")]
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=findings))
    assert result.highest_composite_score == 95.0


def test_distinct_subject_count_deduplicates() -> None:
    findings = [
        _finding(subject="1.2.3.4"),
        _finding(subject="1.2.3.4", category="root_login"),
        _finding(subject="5.6.7.8"),
    ]
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=findings))
    assert result.distinct_subject_count == 2


def test_top_findings_ranked_by_severity_then_score() -> None:
    findings = [
        _finding(severity="low", composite_score=10.0, subject="low-1"),
        _finding(severity="critical", composite_score=50.0, subject="crit-low-score"),
        _finding(severity="critical", composite_score=95.0, subject="crit-high-score"),
    ]
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=findings, top_n=2))
    assert [f.subject for f in result.top_findings] == ["crit-high-score", "crit-low-score"]


def test_top_n_limits_result_count() -> None:
    findings = [_finding(subject=f"1.2.3.{i}") for i in range(10)]
    result = LinuxSecurityAssessmentTool()(LinuxSecurityAssessmentInput(findings=findings, top_n=3))
    assert len(result.top_findings) == 3


def test_deterministic() -> None:
    findings = [_finding()]
    tool = LinuxSecurityAssessmentTool()
    arguments = LinuxSecurityAssessmentInput(findings=findings)
    assert tool(arguments) == tool(arguments)
