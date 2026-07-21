"""Unit tests for core/reporting/completeness_validator.py."""

from __future__ import annotations

import pytest

from core.reporting.completeness_validator import validate_completeness
from core.reporting.models import ReportSection, ReportSectionType, ReportType

pytestmark = pytest.mark.unit


def _section(section_type: ReportSectionType, *, is_empty: bool = False) -> ReportSection:
    return ReportSection(section_type=section_type, title=section_type.value, is_empty=is_empty)


def test_all_required_sections_present_and_non_empty_is_complete() -> None:
    sections = tuple(
        _section(t)
        for t in (
            ReportSectionType.CASE_OVERVIEW,
            ReportSectionType.IOC_SUMMARY,
            ReportSectionType.APPENDIX,
        )
    )
    result = validate_completeness(ReportType.IOC_SUMMARY, sections)
    assert result.is_complete is True
    assert result.missing_section_types == ()
    assert result.duplicate_section_types == ()


def test_missing_required_section_is_reported() -> None:
    sections = (_section(ReportSectionType.CASE_OVERVIEW),)
    result = validate_completeness(ReportType.IOC_SUMMARY, sections)
    assert result.is_complete is False
    assert ReportSectionType.IOC_SUMMARY in result.missing_section_types
    assert ReportSectionType.APPENDIX in result.missing_section_types


def test_duplicate_section_type_is_reported() -> None:
    sections = (
        _section(ReportSectionType.CASE_OVERVIEW),
        _section(ReportSectionType.CASE_OVERVIEW),
        _section(ReportSectionType.IOC_SUMMARY),
        _section(ReportSectionType.APPENDIX),
    )
    result = validate_completeness(ReportType.IOC_SUMMARY, sections)
    assert result.is_complete is False
    assert ReportSectionType.CASE_OVERVIEW in result.duplicate_section_types


def test_all_empty_sections_is_incomplete() -> None:
    sections = tuple(
        _section(t, is_empty=True)
        for t in (
            ReportSectionType.CASE_OVERVIEW,
            ReportSectionType.IOC_SUMMARY,
            ReportSectionType.APPENDIX,
        )
    )
    result = validate_completeness(ReportType.IOC_SUMMARY, sections)
    assert result.is_complete is False
    assert any("empty" in reason for reason in result.reasons)


def test_no_sections_at_all_is_incomplete() -> None:
    result = validate_completeness(ReportType.IOC_SUMMARY, ())
    assert result.is_complete is False
    assert any("No sections" in reason for reason in result.reasons)
