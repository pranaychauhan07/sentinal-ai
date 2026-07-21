"""Unit tests for core/reporting/statistics_calculator.py."""

from __future__ import annotations

import pytest

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportSection, ReportSectionType
from core.reporting.statistics_calculator import calculate_statistics

pytestmark = pytest.mark.unit


def test_statistics_reflect_context_counts() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"title": "f1"},),
        evidence_items=({"evidence_type": "ssh_auth"},),
        iocs=({"ioc_type": "ipv4"},),
        mitre_mappings=({"technique_id": "T1110"},),
        vulnerability_records=({"cve_id": "CVE-2024-1"},),
        skipped_record_count=2,
        incident_response_plan={"recommendations": [{"priority": "p1_immediate"}]},
    )
    sections = (ReportSection(section_type=ReportSectionType.APPENDIX, title="Appendix"),)
    stats = calculate_statistics(context, sections, duration_ms=12.5)

    assert stats.finding_count == 1
    assert stats.evidence_count == 1
    assert stats.ioc_count == 1
    assert stats.mitre_technique_count == 1
    assert stats.vulnerability_count == 1
    assert stats.skipped_record_count == 2
    assert stats.incident_response_recommendation_count == 1
    assert stats.sections_generated_count == 1
    assert stats.generation_duration_ms == 12.5


def test_statistics_handle_malformed_incident_response_plan_recommendations() -> None:
    context = ReportGenerationContext(
        case_id="c1", incident_response_plan={"recommendations": "not-a-list"}
    )
    stats = calculate_statistics(context, ())
    assert stats.incident_response_recommendation_count == 0


def test_statistics_count_empty_sections() -> None:
    context = ReportGenerationContext(case_id="c1")
    sections = (
        ReportSection(section_type=ReportSectionType.APPENDIX, title="Appendix", is_empty=False),
        ReportSection(section_type=ReportSectionType.FINDINGS, title="Findings", is_empty=True),
    )
    stats = calculate_statistics(context, sections)
    assert stats.sections_generated_count == 2
    assert stats.sections_empty_count == 1
