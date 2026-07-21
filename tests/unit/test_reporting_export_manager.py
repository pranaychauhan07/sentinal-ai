"""Unit tests for core/reporting/export_manager.py."""

from __future__ import annotations

import base64

import plotly.graph_objects as go
import pytest

from core.reporting.docx_renderer import DOCXReportRenderer
from core.reporting.exceptions import OversizedReportExportError, UnsupportedExportFormatError
from core.reporting.export_manager import DEFAULT_MAX_REPORT_EXPORT_BYTES, ExportManager
from core.reporting.markdown_renderer import MarkdownReportRenderer
from core.reporting.models import (
    ALL_REPORT_FORMATS,
    GeneratedReport,
    ReportFormat,
    ReportSection,
    ReportSectionType,
    ReportStatistics,
    ReportType,
    ReportValidationResult,
)
from core.reporting.pdf_renderer import PDFReportRenderer

pytestmark = pytest.mark.unit

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class _FakeChartImageEncoder:
    def encode(self, figure: go.Figure, *, width: int = 900, height: int = 500) -> bytes:
        return _TINY_PNG


def _manager() -> ExportManager:
    encoder = _FakeChartImageEncoder()
    return ExportManager(
        pdf_renderer=PDFReportRenderer(chart_image_encoder=encoder),
        docx_renderer=DOCXReportRenderer(chart_image_encoder=encoder),
        markdown_renderer=MarkdownReportRenderer(chart_image_encoder=encoder),
    )


def _report() -> GeneratedReport:
    sections = (
        ReportSection(
            section_type=ReportSectionType.FINDINGS,
            title="Findings",
            content={"finding_count": 1, "findings": [{"title": "x", "severity": "high"}]},
        ),
    )
    return GeneratedReport(
        case_id="case-1",
        report_type=ReportType.TECHNICAL_INVESTIGATION,
        title="Technical Investigation Report",
        sections=sections,
        statistics=ReportStatistics(finding_count=1),
        validation=ReportValidationResult(is_complete=True),
        confidence=0.5,
    )


def test_supported_formats_covers_every_report_format() -> None:
    manager = _manager()
    assert set(manager.supported_formats()) == set(ALL_REPORT_FORMATS)


@pytest.mark.parametrize("export_format", list(ReportFormat))
def test_export_every_format_returns_non_empty_content(export_format: ReportFormat) -> None:
    manager = _manager()
    exported = manager.export(_report(), export_format, include_charts=False)
    assert exported.content
    assert exported.size_bytes == len(exported.content)
    assert exported.format is export_format
    assert exported.filename.endswith(
        export_format.value if export_format != ReportFormat.MARKDOWN else "md"
    )


def test_export_sets_correct_media_type_and_filename() -> None:
    manager = _manager()
    exported = manager.export(_report(), ReportFormat.PDF, include_charts=False)
    assert exported.media_type == "application/pdf"
    assert exported.filename == "case-1_technical_investigation.pdf"


def test_export_rejects_oversized_report() -> None:
    manager = ExportManager(max_export_bytes=10)
    with pytest.raises(OversizedReportExportError):
        manager.export(_report(), ReportFormat.JSON, include_charts=False)


def test_default_max_export_bytes_is_generous() -> None:
    assert DEFAULT_MAX_REPORT_EXPORT_BYTES > 1024 * 1024


def test_json_export_round_trips_through_generated_report() -> None:
    manager = _manager()
    exported = manager.export(_report(), ReportFormat.JSON, include_charts=False)
    round_tripped = GeneratedReport.model_validate_json(exported.content)
    assert round_tripped.case_id == "case-1"


def test_unsupported_format_raises() -> None:
    manager = _manager()
    with pytest.raises(UnsupportedExportFormatError):
        manager.export(_report(), "not-a-real-format", include_charts=False)  # type: ignore[arg-type]
