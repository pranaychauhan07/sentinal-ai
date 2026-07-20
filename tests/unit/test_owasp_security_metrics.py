"""Unit tests for core/owasp_security/metrics.py."""

from __future__ import annotations

import pytest

from core.owasp_security.metrics import SastMetricsCollector

pytestmark = pytest.mark.unit


def test_snapshot_starts_at_zero() -> None:
    snapshot = SastMetricsCollector().snapshot()
    assert snapshot.files_analyzed == 0
    assert snapshot.findings_by_category == {}


def test_records_accumulate() -> None:
    collector = SastMetricsCollector()
    collector.record_file_analyzed(42)
    collector.record_finding("sql_injection")
    collector.record_finding("sql_injection")
    collector.record_rule_match("py_sql_injection")
    collector.record_failure()
    collector.record_processing_time(5.0)

    snapshot = collector.snapshot()
    assert snapshot.files_analyzed == 1
    assert snapshot.lines_analyzed == 42
    assert snapshot.findings_by_category == {"sql_injection": 2}
    assert snapshot.rule_matches_by_id == {"py_sql_injection": 1}
    assert snapshot.failure_count == 1
    assert snapshot.total_processing_ms == 5.0
