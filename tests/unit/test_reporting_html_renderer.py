"""Unit tests for core/reporting/html_renderer.py."""

from __future__ import annotations

import pytest

from core.reporting.html_renderer import HTMLReportRenderer
from core.reporting.models import (
    GeneratedReport,
    ReportSection,
    ReportSectionType,
    ReportStatistics,
    ReportType,
    ReportValidationResult,
)
from core.reporting.theme import DARK_THEME, LIGHT_THEME

pytestmark = pytest.mark.unit


def _report(content: dict[str, object] | None = None) -> GeneratedReport:
    sections = (
        ReportSection(
            section_type=ReportSectionType.FINDINGS,
            title="Findings",
            content=content
            or {"finding_count": 1, "findings": [{"title": "x", "severity": "high"}]},
            is_empty=content is None and False,
        ),
    )
    return GeneratedReport(
        case_id="case-1",
        report_type=ReportType.TECHNICAL_INVESTIGATION,
        title="Technical Investigation Report",
        sections=sections,
        statistics=ReportStatistics(finding_count=1),
        validation=ReportValidationResult(is_complete=True),
        confidence=0.7,
    )


def test_render_produces_valid_html_document() -> None:
    renderer = HTMLReportRenderer()
    html = renderer.render(_report(), include_charts=False)
    assert "<!doctype html>" in html.lower()
    assert "Technical Investigation Report" in html
    assert "case-1" in html


def test_render_escapes_attacker_controlled_finding_text() -> None:
    """The template-injection / XSS defense: a finding title containing
    a `<script>` tag must never appear unescaped in the rendered output —
    constitution §10's "unsafe embedded content" guard, exercised against
    the real `report.html.j2` template, not a synthetic Jinja2 snippet."""
    renderer = HTMLReportRenderer()
    malicious_content = {
        "finding_count": 1,
        "findings": [{"title": "<script>alert(1)</script>", "severity": "high"}],
    }
    html = renderer.render(_report(malicious_content), include_charts=False)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_respects_dark_theme() -> None:
    renderer = HTMLReportRenderer()
    html = renderer.render(_report(), theme=DARK_THEME, include_charts=False)
    assert 'data-theme="dark"' in html


def test_render_respects_light_theme_by_default() -> None:
    renderer = HTMLReportRenderer()
    html = renderer.render(_report(), include_charts=False)
    assert 'data-theme="light"' in html
    assert LIGHT_THEME.primary_color in html


def test_render_embeds_charts_when_requested() -> None:
    renderer = HTMLReportRenderer()
    html = renderer.render(_report(), include_charts=True)
    assert "plotly-graph-div" in html
    assert "Plotly.newPlot" in html or "Plotly" in html


def test_render_bytes_returns_utf8_encoded_html() -> None:
    renderer = HTMLReportRenderer()
    data = renderer.render_bytes(_report(), include_charts=False)
    assert isinstance(data, bytes)
    assert b"Technical Investigation Report" in data
