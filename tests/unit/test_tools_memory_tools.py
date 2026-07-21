"""Unit tests for core/tools/memory_tools.py — deterministic reconstruction/
labeling/aggregation of already-retrieved memory-context data, and the
oversized-context guard (ADR-0028)."""

from __future__ import annotations

import pytest

from core.tools.memory_tools import (
    MAX_TOTAL_ITEMS,
    CategoryRetrievalMetricsInput,
    MemoryContextResolutionInput,
    MemoryContextResolutionOutput,
    MemoryContextResolutionTool,
    RawKnowledgeItem,
    RawSimilarItem,
    confidence_label,
)

pytestmark = pytest.mark.unit


def _tool() -> MemoryContextResolutionTool:
    return MemoryContextResolutionTool()


def test_confidence_label_buckets() -> None:
    assert confidence_label(0.9) == "high"
    assert confidence_label(0.6) == "medium"
    assert confidence_label(0.1) == "low"


def test_empty_input_yields_empty_context_with_degraded_metrics() -> None:
    tool = _tool()
    result = tool(MemoryContextResolutionInput())
    assert isinstance(result, MemoryContextResolutionOutput)
    context = result.context
    assert context.similar_cases == ()
    assert context.metrics.hit is False
    assert context.metrics.query_text_empty is True
    assert context.metrics.degraded is True


def test_resolves_similar_findings_with_labels_and_reasons() -> None:
    tool = _tool()
    result = tool(
        MemoryContextResolutionInput(
            query_text="brute force ssh",
            similar_findings=[
                RawSimilarItem(
                    case_id="11111111-1111-1111-1111-111111111111",
                    record_id="22222222-2222-2222-2222-222222222222",
                    score=0.82,
                    excerpt="repeated failed logins",
                    category="finding",
                    recorded_at="2026-01-01T00:00:00+00:00",
                )
            ],
        )
    )
    findings = result.context.similar_findings
    assert len(findings) == 1
    assert findings[0].confidence_label == "high"
    assert findings[0].recorded_at == "2026-01-01T00:00:00+00:00"
    assert "semantic similarity" in findings[0].reason
    assert result.context.metrics.hit is True
    assert result.context.metrics.total_items_returned == 1


def test_resolves_related_knowledge() -> None:
    tool = _tool()
    result = tool(
        MemoryContextResolutionInput(
            query_text="sql injection",
            related_knowledge=[
                RawKnowledgeItem(
                    source_type="owasp_top10",
                    document_id="A03",
                    title="Injection",
                    content="...",
                    score=0.7,
                )
            ],
        )
    )
    knowledge = result.context.related_knowledge
    assert len(knowledge) == 1
    assert knowledge[0].confidence_label == "medium"
    assert knowledge[0].source == "knowledge_layer"


def test_category_metrics_aggregate_into_retrieval_metrics() -> None:
    tool = _tool()
    result = tool(
        MemoryContextResolutionInput(
            query_text="query",
            category_metrics=[
                CategoryRetrievalMetricsInput(
                    category="finding",
                    raw_candidate_count=10,
                    below_threshold_dropped=4,
                    duplicate_dropped=1,
                    latency_ms=12.0,
                ),
                CategoryRetrievalMetricsInput(
                    category="ioc", raw_candidate_count=3, degraded=True, error="boom"
                ),
            ],
        )
    )
    metrics = result.context.metrics
    assert metrics.categories_queried == 2
    assert metrics.total_candidates_considered == 13
    assert metrics.below_threshold_dropped == 4
    assert metrics.duplicate_dropped == 1
    assert metrics.failed_category_count == 1


def test_oversized_context_guard_truncates_to_max_total_items() -> None:
    tool = _tool()
    many_findings = [
        RawSimilarItem(
            case_id="11111111-1111-1111-1111-111111111111",
            record_id=f"22222222-2222-2222-2222-{i:012d}",
            score=0.9,
            excerpt="x",
            category="finding",
        )
        for i in range(MAX_TOTAL_ITEMS + 20)
    ]
    result = tool(MemoryContextResolutionInput(query_text="query", similar_findings=many_findings))
    total = (
        len(result.context.similar_cases)
        + len(result.context.similar_findings)
        + len(result.context.similar_iocs)
        + len(result.context.similar_mitre_techniques)
        + len(result.context.similar_reports)
        + len(result.context.related_knowledge)
    )
    assert total == MAX_TOTAL_ITEMS
    assert result.context.metrics.oversized_context_truncated == 20


def test_no_hit_when_zero_items_but_query_nonempty() -> None:
    tool = _tool()
    result = tool(MemoryContextResolutionInput(query_text="brute force ssh"))
    assert result.context.metrics.hit is False
    assert result.context.metrics.query_text_empty is False
    assert result.context.metrics.degraded is False
