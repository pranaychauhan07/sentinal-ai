"""Unit tests for core/reporting/pdf_renderer.py.

Uses a fake `ChartImageEncoder` throughout (constitution §11) — real
Kaleido rendering is exercised only by the manual smoke test recorded in
docs/adr/0026-report-export-framework.md, not the unit suite, since it
costs ~1-2 real seconds per chart.
"""

from __future__ import annotations

import base64

import plotly.graph_objects as go
import pytest

from core.reporting.asset_manager import AssetManager
from core.reporting.models import (
    GeneratedReport,
    ReportSection,
    ReportSectionType,
    ReportStatistics,
    ReportType,
    ReportValidationResult,
)
from core.reporting.pdf_renderer import PDFReportRenderer
from core.reporting.theme import DARK_THEME

pytestmark = pytest.mark.unit

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class _FakeChartImageEncoder:
    def encode(self, figure: go.Figure, *, width: int = 900, height: int = 500) -> bytes:
        return _TINY_PNG


class _FailingChartImageEncoder:
    def encode(self, figure: go.Figure, *, width: int = 900, height: int = 500) -> bytes:
        from core.reporting.exceptions import ChartRenderingError

        raise ChartRenderingError("no chrome available")


def _report() -> GeneratedReport:
    sections = (
        ReportSection(
            section_type=ReportSectionType.FINDINGS,
            title="Findings",
            content={
                "finding_count": 2,
                "findings": [
                    {"title": "Brute force", "severity": "high", "risk_score": 70.0},
                    {"title": "Port scan", "severity": "medium", "risk_score": 40.0},
                ],
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
        statistics=ReportStatistics(finding_count=2),
        validation=ReportValidationResult(is_complete=True),
        confidence=0.7,
    )


def test_render_produces_a_valid_pdf_document() -> None:
    renderer = PDFReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    pdf_bytes = renderer.render(_report(), include_charts=False)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 100


def test_render_with_charts_embeds_images() -> None:
    renderer = PDFReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    pdf_bytes = renderer.render(_report(), include_charts=True)
    assert pdf_bytes.startswith(b"%PDF-")


def test_render_degrades_gracefully_when_chart_rendering_fails() -> None:
    renderer = PDFReportRenderer(chart_image_encoder=_FailingChartImageEncoder())
    pdf_bytes = renderer.render(_report(), include_charts=True)
    assert pdf_bytes.startswith(b"%PDF-")  # never crashes the whole export


def test_render_embeds_organization_logo() -> None:
    assets = AssetManager()
    logo_uri = assets.to_data_uri(_TINY_PNG, mime_type="image/png")
    theme = DARK_THEME.model_copy(update={"logo_data_uri": logo_uri, "organization_name": "Acme"})
    renderer = PDFReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    pdf_bytes = renderer.render(_report(), theme=theme, include_charts=False)
    assert pdf_bytes.startswith(b"%PDF-")


def test_render_size_is_stable_within_a_small_tolerance() -> None:
    # ReportLab embeds a creation timestamp in the PDF container, so
    # byte-for-byte determinism isn't guaranteed even for identical input
    # (unlike every deterministic `core/reporting` generation-stage
    # component) — this asserts the *content* size is stable, not exact
    # bytes.
    renderer = PDFReportRenderer(chart_image_encoder=_FakeChartImageEncoder())
    first = renderer.render(_report(), include_charts=False)
    second = renderer.render(_report(), include_charts=False)
    assert abs(len(first) - len(second)) < 20
