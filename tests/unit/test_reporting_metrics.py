"""Unit tests for core/reporting/metrics.py."""

from __future__ import annotations

import pytest

from core.reporting.metrics import ReportExportMetricsCollector, ReportGenerationMetricsCollector

pytestmark = pytest.mark.unit


def test_collector_accumulates_and_snapshots() -> None:
    collector = ReportGenerationMetricsCollector()
    collector.record_report_generated()
    collector.record_section_generated()
    collector.record_section_generated()
    collector.record_section_failed()
    collector.record_processing_time(10.0)
    collector.record_processing_time(5.0)

    snapshot = collector.snapshot()
    assert snapshot.reports_generated == 1
    assert snapshot.sections_generated == 2
    assert snapshot.sections_failed == 1
    assert snapshot.total_processing_ms == 15.0


def test_export_collector_accumulates_and_snapshots() -> None:
    collector = ReportExportMetricsCollector()
    collector.record_export_generated("pdf")
    collector.record_export_generated("pdf")
    collector.record_export_generated("html")
    collector.record_export_failed("docx")
    collector.record_processing_time(100.0)

    snapshot = collector.snapshot()
    assert snapshot.exports_generated == 3
    assert snapshot.exports_failed == 1
    assert snapshot.exports_by_format == {"pdf": 2, "html": 1}
    assert snapshot.failures_by_format == {"docx": 1}
    assert snapshot.total_processing_ms == 100.0
