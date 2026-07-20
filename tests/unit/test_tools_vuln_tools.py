"""Unit tests for core/tools/vuln_tools.py."""

from __future__ import annotations

import pytest

from core.tools.vuln_tools import (
    VulnerabilityAssessmentInput,
    VulnerabilityAssessmentTool,
    VulnerabilityFindingSummaryInput,
)

pytestmark = pytest.mark.unit


def _finding(**overrides: object) -> VulnerabilityFindingSummaryInput:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell",
        "severity": "critical",
        "priority": "p1_critical",
        "composite_score": 95.0,
        "affected_asset_ids": ("10.0.0.5", "10.0.0.6"),
    }
    defaults.update(overrides)
    return VulnerabilityFindingSummaryInput(**defaults)  # type: ignore[arg-type]


def test_empty_findings_returns_zeroed_summary() -> None:
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=[]))
    assert result.finding_count == 0
    assert result.severity_counts == {}
    assert result.highest_composite_score == 0.0
    assert result.top_findings == ()


def test_counts_by_severity() -> None:
    findings = [
        _finding(severity="critical"),
        _finding(severity="critical", cve_id="CVE-2021-2"),
        _finding(severity="low", cve_id="CVE-2021-3"),
    ]
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=findings))
    assert result.finding_count == 3
    assert result.severity_counts == {"critical": 2, "low": 1}


def test_highest_composite_score() -> None:
    findings = [_finding(composite_score=40.0), _finding(composite_score=95.0)]
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=findings))
    assert result.highest_composite_score == 95.0


def test_distinct_asset_count_deduplicates_across_findings() -> None:
    findings = [
        _finding(affected_asset_ids=("10.0.0.5", "10.0.0.6")),
        _finding(affected_asset_ids=("10.0.0.6", "10.0.0.7"), cve_id="CVE-2021-2"),
    ]
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=findings))
    assert result.distinct_asset_count == 3


def test_top_findings_ranked_by_priority_then_score() -> None:
    findings = [
        _finding(priority="p4_low", composite_score=10.0, cve_id="low-1"),
        _finding(priority="p1_critical", composite_score=50.0, cve_id="crit-low-score"),
        _finding(priority="p1_critical", composite_score=95.0, cve_id="crit-high-score"),
    ]
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=findings, top_n=2))
    assert [f.cve_id for f in result.top_findings] == ["crit-high-score", "crit-low-score"]


def test_top_n_limits_result_count() -> None:
    findings = [_finding(cve_id=f"CVE-{i}") for i in range(10)]
    result = VulnerabilityAssessmentTool()(VulnerabilityAssessmentInput(findings=findings, top_n=3))
    assert len(result.top_findings) == 3


def test_deterministic() -> None:
    findings = [_finding()]
    tool = VulnerabilityAssessmentTool()
    arguments = VulnerabilityAssessmentInput(findings=findings)
    assert tool(arguments) == tool(arguments)
