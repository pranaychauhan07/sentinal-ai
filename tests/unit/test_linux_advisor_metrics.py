"""Unit tests for core/linux_advisor/metrics.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.metrics import LinuxAdvisorMetricsCollector

pytestmark = pytest.mark.unit


def test_empty_snapshot() -> None:
    snapshot = LinuxAdvisorMetricsCollector().snapshot()
    assert snapshot.commands_analyzed == 0
    assert snapshot.permissions_analyzed == 0
    assert snapshot.rule_matches_by_id == {}
    assert snapshot.failure_count == 0


def test_record_command_and_permission() -> None:
    collector = LinuxAdvisorMetricsCollector()
    collector.record_command_analyzed()
    collector.record_command_analyzed()
    collector.record_permission_analyzed()
    snapshot = collector.snapshot()
    assert snapshot.commands_analyzed == 2
    assert snapshot.permissions_analyzed == 1


def test_record_rule_match_counts_by_id() -> None:
    collector = LinuxAdvisorMetricsCollector()
    collector.record_rule_match("chmod_777")
    collector.record_rule_match("chmod_777")
    collector.record_rule_match("rm_rf_root")
    snapshot = collector.snapshot()
    assert snapshot.rule_matches_by_id == {"chmod_777": 2, "rm_rf_root": 1}


def test_record_failure() -> None:
    collector = LinuxAdvisorMetricsCollector()
    collector.record_failure()
    assert collector.snapshot().failure_count == 1


def test_record_processing_time_accumulates() -> None:
    collector = LinuxAdvisorMetricsCollector()
    collector.record_processing_time(10.0)
    collector.record_processing_time(5.0)
    assert collector.snapshot().total_processing_ms == 15.0


def test_snapshot_is_independent_copy() -> None:
    collector = LinuxAdvisorMetricsCollector()
    collector.record_command_analyzed()
    snapshot = collector.snapshot()
    collector.record_command_analyzed()
    assert snapshot.commands_analyzed == 1
    assert collector.snapshot().commands_analyzed == 2
