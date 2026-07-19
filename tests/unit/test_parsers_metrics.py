"""Unit tests for core/parsers/metrics.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.parsers.base import ParserRunResult
from core.parsers.metrics import ParserMetricsCollector


def _run_result(succeeded: bool, duration_ms: float) -> ParserRunResult:
    started = datetime.now(UTC)
    return ParserRunResult(
        parser_name="ssh_auth",
        succeeded=succeeded,
        started_at=started,
        completed_at=started + timedelta(milliseconds=duration_ms),
    )


@pytest.mark.unit
def test_record_run_accumulates_stats() -> None:
    collector = ParserMetricsCollector()
    collector.record_run("ssh_auth", _run_result(True, 10))
    collector.record_run("ssh_auth", _run_result(False, 20))

    stats = collector.stats_for("ssh_auth")
    assert stats.attempts == 2
    assert stats.successes == 1
    assert stats.degraded == 1
    assert stats.success_rate == 0.5
    assert stats.average_duration_ms == pytest.approx(15, abs=0.5)


@pytest.mark.unit
def test_stats_for_unknown_parser_is_zeroed() -> None:
    collector = ParserMetricsCollector()
    stats = collector.stats_for("unknown")
    assert stats.attempts == 0
    assert stats.success_rate == 0.0
    assert stats.average_duration_ms == 0.0


@pytest.mark.unit
def test_snapshot_is_a_copy_not_a_live_view() -> None:
    collector = ParserMetricsCollector()
    collector.record_run("ssh_auth", _run_result(True, 5))
    snapshot = collector.snapshot()
    collector.record_run("ssh_auth", _run_result(True, 5))
    assert snapshot.by_parser["ssh_auth"].attempts == 1
