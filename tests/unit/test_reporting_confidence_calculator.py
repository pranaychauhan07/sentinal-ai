"""Unit tests for core/reporting/confidence_calculator.py."""

from __future__ import annotations

import pytest

from core.reporting.confidence_calculator import calculate_report_confidence
from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportSection, ReportSectionType, ReportValidationResult

pytestmark = pytest.mark.unit


def test_no_sections_yields_zero_confidence() -> None:
    context = ReportGenerationContext(case_id="c1")
    result = calculate_report_confidence(
        context, (), ReportValidationResult(is_complete=False, reasons=("no sections",))
    )
    assert result == 0.0


def test_all_non_empty_sections_and_complete_validation_yields_high_confidence() -> None:
    context = ReportGenerationContext(case_id="c1", findings=({"title": "f1"},))
    sections = (
        ReportSection(section_type=ReportSectionType.FINDINGS, title="Findings", is_empty=False),
    )
    result = calculate_report_confidence(
        context, sections, ReportValidationResult(is_complete=True)
    )
    assert result == 1.0


def test_skipped_records_discount_confidence() -> None:
    context = ReportGenerationContext(
        case_id="c1", findings=({"title": "f1"},), skipped_record_count=1
    )
    sections = (
        ReportSection(section_type=ReportSectionType.FINDINGS, title="Findings", is_empty=False),
    )
    result = calculate_report_confidence(
        context, sections, ReportValidationResult(is_complete=True)
    )
    assert result == 0.5


def test_incomplete_validation_discounts_confidence() -> None:
    context = ReportGenerationContext(case_id="c1", findings=({"title": "f1"},))
    sections = (
        ReportSection(section_type=ReportSectionType.FINDINGS, title="Findings", is_empty=False),
    )
    result = calculate_report_confidence(
        context, sections, ReportValidationResult(is_complete=False, reasons=("missing",))
    )
    assert result == 0.75


def test_confidence_is_always_within_bounds() -> None:
    context = ReportGenerationContext(case_id="c1")
    sections = (
        ReportSection(section_type=ReportSectionType.APPENDIX, title="Appendix", is_empty=True),
    )
    result = calculate_report_confidence(
        context, sections, ReportValidationResult(is_complete=False)
    )
    assert 0.0 <= result <= 1.0
