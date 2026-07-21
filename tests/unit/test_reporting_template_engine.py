"""Unit tests for core/reporting/template_engine.py."""

from __future__ import annotations

import pytest

from core.reporting.exceptions import TemplateRenderError
from core.reporting.template_engine import ReportTemplateEngine

pytestmark = pytest.mark.unit


def test_rejects_unknown_template_name() -> None:
    engine = ReportTemplateEngine()
    with pytest.raises(TemplateRenderError):
        engine.render("not-a-real-template.j2")


def test_known_templates_allowlist_contains_report_template() -> None:
    from core.reporting.template_engine import KNOWN_TEMPLATES

    assert "report.html.j2" in KNOWN_TEMPLATES
