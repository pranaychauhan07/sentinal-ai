"""Unit tests for core/reporting/metrics.py."""

from __future__ import annotations

import pytest

from core.reporting.metrics import ReportGenerationMetricsCollector

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
