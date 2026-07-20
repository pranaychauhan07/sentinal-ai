"""Unit tests for core/linux_security/metrics.py."""

from __future__ import annotations

import pytest

from core.linux_security.metrics import LinuxSecurityMetricsCollector

pytestmark = pytest.mark.unit


def test_record_run_tracks_attempts_and_successes() -> None:
    collector = LinuxSecurityMetricsCollector()
    collector.record_run(succeeded=True, candidate_count=3, skipped_records=1)
    collector.record_run(succeeded=False, candidate_count=0, skipped_records=5)
    snapshot = collector.snapshot()
    assert snapshot.stats.attempts == 2
    assert snapshot.stats.successes == 1
    assert snapshot.stats.degraded == 1
    assert snapshot.stats.total_candidates == 3
    assert snapshot.stats.total_skipped_records == 6
    assert snapshot.stats.success_rate == 0.5


def test_success_rate_zero_when_no_attempts() -> None:
    collector = LinuxSecurityMetricsCollector()
    assert collector.snapshot().stats.success_rate == 0.0


def test_record_candidate_tracks_distributions() -> None:
    collector = LinuxSecurityMetricsCollector()
    collector.record_candidate(category="brute_force", severity="high")
    collector.record_candidate(category="brute_force", severity="high")
    collector.record_candidate(category="root_login", severity="high")
    snapshot = collector.snapshot()
    assert snapshot.candidate_counts_by_category == {"brute_force": 2, "root_login": 1}
    assert snapshot.candidate_counts_by_severity == {"high": 3}


def test_record_rejected_increments_count() -> None:
    collector = LinuxSecurityMetricsCollector()
    collector.record_rejected()
    collector.record_rejected()
    assert collector.snapshot().rejected_count == 2


def test_collectors_are_isolated_per_instance() -> None:
    a = LinuxSecurityMetricsCollector()
    b = LinuxSecurityMetricsCollector()
    a.record_rejected()
    assert b.snapshot().rejected_count == 0
