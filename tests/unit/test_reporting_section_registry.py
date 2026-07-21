"""Unit tests for core/reporting/section_registry.py."""

from __future__ import annotations

import pytest

from core.reporting.models import ReportSectionType, ReportType
from core.reporting.section_registry import REPORT_TYPE_SECTIONS, default_title_for

pytestmark = pytest.mark.unit


def test_every_report_type_has_a_section_mapping() -> None:
    for report_type in ReportType:
        assert report_type in REPORT_TYPE_SECTIONS
        assert len(REPORT_TYPE_SECTIONS[report_type]) > 0


def test_every_report_type_has_a_default_title() -> None:
    for report_type in ReportType:
        title = default_title_for(report_type)
        assert isinstance(title, str)
        assert title


def test_technical_investigation_includes_findings_and_mitre_mapping() -> None:
    sections = REPORT_TYPE_SECTIONS[ReportType.TECHNICAL_INVESTIGATION]
    assert ReportSectionType.FINDINGS in sections
    assert ReportSectionType.MITRE_MAPPING in sections
    assert ReportSectionType.RECOMMENDATIONS in sections
