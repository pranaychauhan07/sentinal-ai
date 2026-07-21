"""Unit tests for core/conversation/metrics.py."""

from __future__ import annotations

import pytest

from core.conversation.metrics import ConversationMetricsCollector


@pytest.mark.unit
def test_metrics_snapshot_reflects_recorded_events() -> None:
    collector = ConversationMetricsCollector()
    collector.record_question_answered()
    collector.record_retrieval_result(item_count=3)
    collector.record_retrieval_result(item_count=0)
    collector.record_citations(2)
    collector.record_degraded_answer()
    collector.record_prompt_injection_flag()
    collector.record_validation_failure()
    collector.record_processing_time(12.5)

    snapshot = collector.snapshot()
    assert snapshot.questions_answered == 1
    assert snapshot.retrieval_hits == 1
    assert snapshot.retrieval_misses == 1
    assert snapshot.citations_attached == 2
    assert snapshot.degraded_answers == 1
    assert snapshot.prompt_injection_flags == 1
    assert snapshot.validation_failures == 1
    assert snapshot.total_processing_ms == 12.5
