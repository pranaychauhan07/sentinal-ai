"""Unit tests for core/threat_intel/metrics.py — ThreatIntelMetricsCollector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.threat_intel.base import ExtractorRunResult
from core.threat_intel.metrics import ThreatIntelMetricsCollector


def _run_result(*, succeeded: bool, candidate_count: int = 1) -> ExtractorRunResult:
    started = datetime.now(UTC)
    return ExtractorRunResult(
        extractor_name="engine",
        succeeded=succeeded,
        candidate_count=candidate_count,
        started_at=started,
        completed_at=started + timedelta(milliseconds=10),
    )


@pytest.mark.unit
def test_record_run_accumulates_stats() -> None:
    collector = ThreatIntelMetricsCollector()
    collector.record_run("engine", _run_result(succeeded=True))
    collector.record_run("engine", _run_result(succeeded=False))

    stats = collector.stats_for("engine")
    assert stats.attempts == 2
    assert stats.successes == 1
    assert stats.degraded == 1
    assert stats.success_rate == 0.5


@pytest.mark.unit
def test_stats_for_unknown_extractor_returns_empty_stats() -> None:
    collector = ThreatIntelMetricsCollector()
    stats = collector.stats_for("nonexistent")
    assert stats.attempts == 0
    assert stats.success_rate == 0.0


@pytest.mark.unit
def test_record_rule_match_and_ioc_counters() -> None:
    collector = ThreatIntelMetricsCollector()
    collector.record_rule_match("r1")
    collector.record_rule_match("r1")
    collector.record_ioc("ipv4")

    snapshot = collector.snapshot()
    assert snapshot.rule_match_counts["r1"] == 2
    assert snapshot.ioc_counts_by_type["ipv4"] == 1


@pytest.mark.unit
def test_snapshot_is_a_copy_not_live_reference() -> None:
    collector = ThreatIntelMetricsCollector()
    collector.record_run("engine", _run_result(succeeded=True))
    snapshot = collector.snapshot()
    collector.record_run("engine", _run_result(succeeded=True))
    assert snapshot.by_extractor["engine"].attempts == 1
