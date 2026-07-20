"""Unit tests for core/vulnerabilities/metrics.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.vulnerabilities.extractor import ExtractorRunResult
from core.vulnerabilities.metrics import VulnerabilityMetricsCollector

pytestmark = pytest.mark.unit


def _run_result(*, succeeded: bool, candidate_count: int = 5) -> ExtractorRunResult:
    started = datetime.now(UTC)
    return ExtractorRunResult(
        extractor_name="vulnerability_extraction_engine",
        succeeded=succeeded,
        candidate_count=candidate_count,
        started_at=started,
        completed_at=started,
    )


def test_record_run_accumulates_stats() -> None:
    collector = VulnerabilityMetricsCollector()
    collector.record_run("engine", _run_result(succeeded=True))
    collector.record_run("engine", _run_result(succeeded=False))
    stats = collector.stats_for("engine")
    assert stats.attempts == 2
    assert stats.successes == 1
    assert stats.degraded == 1
    assert stats.total_candidates == 10


def test_success_rate_and_average_duration() -> None:
    collector = VulnerabilityMetricsCollector()
    collector.record_run("engine", _run_result(succeeded=True))
    stats = collector.stats_for("engine")
    assert stats.success_rate == 1.0
    assert stats.average_duration_ms >= 0.0


def test_unknown_extractor_returns_zeroed_stats() -> None:
    stats = VulnerabilityMetricsCollector().stats_for("never_ran")
    assert stats.attempts == 0
    assert stats.success_rate == 0.0
    assert stats.average_duration_ms == 0.0


def test_record_vulnerability_and_dedup_and_rejected_counters() -> None:
    collector = VulnerabilityMetricsCollector()
    collector.record_vulnerability(severity="critical", detection_source="nessus")
    collector.record_vulnerability(severity="critical", detection_source="nessus")
    collector.record_dedup_merge()
    collector.record_rejected()

    snapshot = collector.snapshot()
    assert snapshot.vulnerability_counts_by_severity["critical"] == 2
    assert snapshot.vulnerability_counts_by_source["nessus"] == 2
    assert snapshot.dedup_merge_count == 1
    assert snapshot.rejected_count == 1


def test_snapshot_is_a_copy_not_a_live_view() -> None:
    collector = VulnerabilityMetricsCollector()
    collector.record_run("engine", _run_result(succeeded=True))
    snapshot = collector.snapshot()
    collector.record_run("engine", _run_result(succeeded=True))
    assert snapshot.by_extractor["engine"].attempts == 1
