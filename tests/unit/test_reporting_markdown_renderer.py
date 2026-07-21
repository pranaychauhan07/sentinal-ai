"""Unit tests for core/reporting/markdown_renderer.py."""

from __future__ import annotations

import base64

import plotly.graph_objects as go
import pytest

from core.reporting.markdown_renderer import MarkdownReportRenderer
from core.reporting.models import (
    GeneratedReport,
    ReportSection,
    ReportSectionType,
    ReportStatistics,
    ReportType,
    ReportValidationResult,
)

pytestmark = pytest.mark.unit

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class _FakeChartImageEncoder:
    """Fast, deterministic stand-in for `KaleidoChartImageEncoder`
    (constitution §11, "mock at the boundary")."""

    def encode(self, figure: go.Figure, *, width: int = 900, height: int = 500) -> bytes:
        return _TINY_PNG


def _report() -> GeneratedReport:
    sections = (
        ReportSection(
            section_type=ReportSectionType.FINDINGS,
            title="Findings",
            content={
                "finding_count": 1,
                "findings": [{"title": "SQL | Injection *risk*", "severity": "high"}],
            },
        ),
        ReportSection(
            section_type=ReportSectionType.APPENDIX, title="Appendix", content={}, is_empty=True
        ),
    )
    return GeneratedReport(
        case_id="case-1",
        report_type=ReportType.TECHNICAL_INVESTIGATION,
        title="Technical Investigation Report",
        sections=sections,
        statistics=ReportStatistics(finding_count=1),
        validation=ReportValidationResult(is_complete=True),
        confidence=0.6,
    )


def test_render_produces_headings_and_toc() -> None:
    renderer = MarkdownReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    markdown = renderer.render(_report(), include_charts=False)
    assert markdown.startswith("# Technical Investigation Report")
    assert "## Table of Contents" in markdown
    assert "## Findings" in markdown


def test_render_escapes_markdown_special_characters() -> None:
    renderer = MarkdownReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    markdown = renderer.render(_report(), include_charts=False)
    assert "SQL | Injection" not in markdown  # unescaped pipe would corrupt table layout
    assert "\\|" in markdown


def test_empty_section_notes_no_data() -> None:
    renderer = MarkdownReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    markdown = renderer.render(_report(), include_charts=False)
    assert "No data available for this section." in markdown


def test_render_embeds_charts_as_data_uri_images() -> None:
    renderer = MarkdownReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    markdown = renderer.render(_report(), include_charts=True)
    assert "![Severity Distribution](data:image/png;base64," in markdown


def test_render_bytes_returns_utf8_encoded_markdown() -> None:
    renderer = MarkdownReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    data = renderer.render_bytes(_report(), include_charts=False)
    assert isinstance(data, bytes)
    assert b"# Technical Investigation Report" in data
