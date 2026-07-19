"""Unit tests for core/findings/metrics.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.findings.base import MappingRunResult
from core.findings.metrics import FindingsMetricsCollector


def _run(succeeded: bool = True, mapping_count: int = 3) -> MappingRunResult:
    now = datetime.now(UTC)
    return MappingRunResult(
        engine_name="mitre_mapping_engine",
        succeeded=succeeded,
        mapping_count=mapping_count,
        started_at=now,
        completed_at=now,
    )


@pytest.mark.unit
def test_record_run_accumulates_stats() -> None:
    collector = FindingsMetricsCollector()
    collector.record_run("mitre_mapping_engine", _run())
    collector.record_run("mitre_mapping_engine", _run(succeeded=False, mapping_count=0))

    stats = collector.stats_for("mitre_mapping_engine")
    assert stats.attempts == 2
    assert stats.successes == 1
    assert stats.degraded == 1
    assert stats.total_mappings == 3


@pytest.mark.unit
def test_stats_for_unknown_engine_returns_empty_stats() -> None:
    collector = FindingsMetricsCollector()
    stats = collector.stats_for("nonexistent")
    assert stats.attempts == 0
    assert stats.success_rate == 0.0


@pytest.mark.unit
def test_snapshot_reflects_finding_and_dedup_counters() -> None:
    collector = FindingsMetricsCollector()
    collector.record_finding_generated()
    collector.record_finding_generated()
    collector.record_finding_merged()
    collector.record_duplicate_rejected()
    collector.record_technique_match("T1110")

    snapshot = collector.snapshot()
    assert snapshot.findings_generated == 2
    assert snapshot.findings_merged == 1
    assert snapshot.duplicate_candidates_rejected == 1
    assert snapshot.technique_match_counts == {"T1110": 1}
