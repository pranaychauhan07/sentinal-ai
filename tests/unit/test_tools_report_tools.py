"""Unit tests for core/tools/report_tools.py."""

from __future__ import annotations

import pytest

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportType
from core.tools.report_tools import ReportGenerationInput, ReportGenerationTool

pytestmark = pytest.mark.unit


def test_run_delegates_to_engine_and_returns_typed_output() -> None:
    tool = ReportGenerationTool()
    context = ReportGenerationContext(
        case_id="c1", findings=({"finding_id": "f1", "title": "x", "severity": "high"},)
    )
    output = tool.run(
        ReportGenerationInput(context=context, report_type=ReportType.TECHNICAL_INVESTIGATION)
    )
    assert output.report.case_id == "c1"
    assert output.report.report_type is ReportType.TECHNICAL_INVESTIGATION


def test_default_report_type_is_technical_investigation() -> None:
    input_model = ReportGenerationInput(context=ReportGenerationContext(case_id="c1"))
    assert input_model.report_type is ReportType.TECHNICAL_INVESTIGATION


def test_tool_call_via_call_operator_works() -> None:
    tool = ReportGenerationTool()
    context = ReportGenerationContext(case_id="c1")
    output = tool(ReportGenerationInput(context=context, report_type=ReportType.IOC_SUMMARY))
    assert output.report.report_type is ReportType.IOC_SUMMARY
