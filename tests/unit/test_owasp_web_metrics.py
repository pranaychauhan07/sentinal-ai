"""Unit tests for core/owasp_web/metrics.py."""

from __future__ import annotations

import pytest

from core.owasp_web.metrics import WebSecurityMetricsCollector

pytestmark = pytest.mark.unit


def test_snapshot_starts_at_zero() -> None:
    snapshot = WebSecurityMetricsCollector().snapshot()
    assert snapshot.headers_analyzed == 0
    assert snapshot.rule_matches_by_id == {}


def test_records_accumulate() -> None:
    collector = WebSecurityMetricsCollector()
    collector.record_header_analyzed()
    collector.record_cookie_analyzed()
    collector.record_jwt_analyzed()
    collector.record_misconfiguration_candidate_analyzed()
    collector.record_rule_match("csp_unsafe_inline")
    collector.record_rule_match("csp_unsafe_inline")
    collector.record_failure()
    collector.record_processing_time(12.5)

    snapshot = collector.snapshot()
    assert snapshot.headers_analyzed == 1
    assert snapshot.cookies_analyzed == 1
    assert snapshot.jwts_analyzed == 1
    assert snapshot.misconfiguration_candidates_analyzed == 1
    assert snapshot.rule_matches_by_id == {"csp_unsafe_inline": 2}
    assert snapshot.failure_count == 1
    assert snapshot.total_processing_ms == 12.5
