"""Unit tests for core/reporting/models.py."""

from __future__ import annotations

import pytest

from core.reporting.models import (
    ALL_REPORT_FORMATS,
    GeneratedReport,
    ReportFormat,
    ReportSection,
    ReportSectionType,
    ReportType,
    ReportValidationResult,
)

pytestmark = pytest.mark.unit


def test_report_type_preserves_original_two_values() -> None:
    assert ReportType.MODULE.value == "module"
    assert ReportType.EXECUTIVE.value == "executive"


def test_report_type_has_eight_task_named_report_types() -> None:
    named = {
        ReportType.EXECUTIVE,
        ReportType.TECHNICAL_INVESTIGATION,
        ReportType.INCIDENT_RESPONSE,
        ReportType.IOC_SUMMARY,
        ReportType.MITRE_ATTACK,
        ReportType.TIMELINE,
        ReportType.THREAT_INTELLIGENCE,
        ReportType.EVIDENCE,
    }
    assert len(named) == 8


def test_all_report_formats_covers_pdf_html_markdown_json_docx() -> None:
    assert set(ALL_REPORT_FORMATS) == {
        ReportFormat.PDF,
        ReportFormat.HTML,
        ReportFormat.MARKDOWN,
        ReportFormat.JSON,
        ReportFormat.DOCX,
    }


def test_generated_report_section_lookup() -> None:
    section = ReportSection(
        section_type=ReportSectionType.CASE_OVERVIEW, title="Case Overview", content={"a": 1}
    )
    report = GeneratedReport(
        case_id="c1",
        report_type=ReportType.EVIDENCE,
        title="Evidence Report",
        sections=(section,),
        validation=ReportValidationResult(is_complete=True),
        confidence=1.0,
    )
    assert report.section(ReportSectionType.CASE_OVERVIEW) is section
    assert report.section(ReportSectionType.FINDINGS) is None


def test_generated_report_confidence_bounds_enforced() -> None:
    with pytest.raises(ValueError):
        GeneratedReport(
            case_id="c1",
            report_type=ReportType.EVIDENCE,
            title="Evidence Report",
            validation=ReportValidationResult(is_complete=True),
            confidence=1.5,
        )
