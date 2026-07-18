"""Unit tests for core/memory/metrics.py."""

from __future__ import annotations

import time

import pytest

from core.memory.metrics import MemoryMetricsCollector

pytestmark = pytest.mark.unit


def test_snapshot_starts_at_zero() -> None:
    collector = MemoryMetricsCollector()
    metrics = collector.snapshot()
    assert metrics.hits == 0
    assert metrics.misses == 0
    assert metrics.hit_rate == 0.0
    assert metrics.average_retrieval_ms == 0.0


def test_hit_rate_reflects_recorded_hits_and_misses() -> None:
    collector = MemoryMetricsCollector()
    collector.record_hit()
    collector.record_hit()
    collector.record_miss()
    metrics = collector.snapshot()
    assert metrics.hit_rate == pytest.approx(2 / 3)


def test_record_write_and_eviction_increment_counters() -> None:
    collector = MemoryMetricsCollector()
    collector.record_write()
    collector.record_eviction(3)
    metrics = collector.snapshot()
    assert metrics.writes == 1
    assert metrics.evictions == 3


def test_time_retrieval_records_duration_and_count() -> None:
    collector = MemoryMetricsCollector()
    with collector.time_retrieval():
        time.sleep(0.001)
    metrics = collector.snapshot()
    assert metrics.retrieval_count == 1
    assert metrics.average_retrieval_ms > 0.0


def test_snapshot_is_a_copy_not_a_live_reference() -> None:
    collector = MemoryMetricsCollector()
    snapshot = collector.snapshot()
    collector.record_hit()
    assert snapshot.hits == 0
