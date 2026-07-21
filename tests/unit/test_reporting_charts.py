"""Unit tests for core/reporting/charts.py."""

from __future__ import annotations

import plotly.graph_objects as go
import pytest

from core.reporting.charts import (
    CHART_BUILDERS,
    build_all_charts,
    case_statistics_chart,
    finding_distribution_chart,
    ioc_category_chart,
    mitre_heatmap_chart,
    risk_trend_chart,
    severity_distribution_chart,
    threat_intelligence_sources_chart,
    timeline_chart,
)
from core.reporting.models import (
    GeneratedReport,
    ReportSection,
    ReportSectionType,
    ReportStatistics,
    ReportType,
    ReportValidationResult,
)

pytestmark = pytest.mark.unit


def _report(sections: tuple[ReportSection, ...] = (), **stats_kwargs: int) -> GeneratedReport:
    return GeneratedReport(
        case_id="case-1",
        report_type=ReportType.TECHNICAL_INVESTIGATION,
        title="Report",
        sections=sections,
        statistics=ReportStatistics(**stats_kwargs),
        validation=ReportValidationResult(is_complete=True),
        confidence=0.5,
    )


def _section(section_type: ReportSectionType, content: dict[str, object]) -> ReportSection:
    return ReportSection(section_type=section_type, title="x", content=content, is_empty=False)


def test_every_chart_builder_degrades_gracefully_on_empty_report() -> None:
    empty_report = _report()
    for name, builder in CHART_BUILDERS.items():
        figure = builder(empty_report)
        assert isinstance(figure, go.Figure), name


def test_build_all_charts_returns_one_entry_per_builder() -> None:
    charts = build_all_charts(_report())
    assert set(charts) == set(CHART_BUILDERS)


def test_severity_distribution_chart_uses_risk_assessment_breakdown() -> None:
    report = _report(
        (
            _section(
                ReportSectionType.RISK_ASSESSMENT,
                {"severity_breakdown": {"high": 3, "low": 1}, "overall_risk_level": "high"},
            ),
        )
    )
    figure = severity_distribution_chart(report)
    assert figure.data
    assert set(figure.data[0].labels) == {"high", "low"}


def test_ioc_category_chart_uses_ioc_summary_by_type() -> None:
    report = _report(
        (_section(ReportSectionType.IOC_SUMMARY, {"iocs_by_type": {"ipv4": 5, "domain": 2}}),)
    )
    figure = ioc_category_chart(report)
    assert list(figure.data[0].x) == ["domain", "ipv4"]
    assert list(figure.data[0].y) == [2, 5]


def test_mitre_heatmap_chart_builds_tactic_technique_grid() -> None:
    report = _report(
        (
            _section(
                ReportSectionType.MITRE_MAPPING,
                {
                    "techniques": [
                        {"technique_id": "T1110", "confidence": 0.9, "tactic_ids": ["TA0006"]}
                    ]
                },
            ),
        )
    )
    figure = mitre_heatmap_chart(report)
    assert figure.data
    assert figure.data[0].x == ("T1110",)
    assert figure.data[0].y == ("TA0006",)


def test_finding_distribution_chart_groups_by_source() -> None:
    report = _report(
        (
            _section(
                ReportSectionType.FINDINGS,
                {
                    "findings": [
                        {"source": "finding", "title": "a", "severity": "high"},
                        {"source": "finding", "title": "b", "severity": "low"},
                        {"source": "vulnerability_assessment", "title": "c", "severity": "medium"},
                    ]
                },
            ),
        )
    )
    figure = finding_distribution_chart(report)
    assert dict(zip(figure.data[0].x, figure.data[0].y, strict=True)) == {
        "finding": 2,
        "vulnerability_assessment": 1,
    }


def test_threat_intelligence_sources_chart_uses_summary_counts() -> None:
    report = _report(
        (
            _section(
                ReportSectionType.THREAT_INTELLIGENCE_SUMMARY,
                {"ioc_count": 4, "distinct_mitre_technique_count": 2},
            ),
        )
    )
    figure = threat_intelligence_sources_chart(report)
    assert list(figure.data[0].y) == [4, 2]


def test_timeline_and_risk_trend_charts_use_investigation_timeline_entries() -> None:
    entries = [
        {
            "agent_name": "soc_analyst",
            "thought": "t1",
            "confidence": 0.7,
            "created_at": "2026-01-01",
        },
        {
            "agent_name": "mitre_agent",
            "thought": "t2",
            "confidence": 0.9,
            "created_at": "2026-01-02",
        },
    ]
    report = _report((_section(ReportSectionType.INVESTIGATION_TIMELINE, {"entries": entries}),))
    timeline_figure = timeline_chart(report)
    trend_figure = risk_trend_chart(report)
    assert len(timeline_figure.data[0].x) == 2
    assert list(trend_figure.data[0].y) == [0.7, 0.9]


def test_case_statistics_chart_skips_zero_valued_fields() -> None:
    report = _report(finding_count=5, evidence_count=0, ioc_count=2)
    figure = case_statistics_chart(report)
    assert "Findings" in figure.data[0].x
    assert "IOCs" in figure.data[0].x
    assert "Evidence Items" not in figure.data[0].x
