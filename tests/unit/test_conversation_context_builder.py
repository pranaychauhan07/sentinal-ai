"""Unit tests for core/conversation/context_builder.py."""

from __future__ import annotations

import pytest

from core.conversation.context_builder import ConversationContextBuilder
from core.conversation.models import EvidenceCategory, RetrievedItem, SourceReference


def _item(source_id: str, score: float, text: str = "x") -> RetrievedItem:
    return RetrievedItem(
        category=EvidenceCategory.FINDING,
        source_id=source_id,
        text=text,
        relevance_score=score,
        reference=SourceReference(
            category=EvidenceCategory.FINDING, source_id=source_id, summary="s"
        ),
    )


@pytest.mark.unit
def test_rank_orders_by_relevance_descending() -> None:
    builder = ConversationContextBuilder()
    items = [_item("low", 0.2), _item("high", 0.9), _item("mid", 0.5)]
    ranked = builder.rank(items)
    assert [item.source_id for item in ranked] == ["high", "mid", "low"]


@pytest.mark.unit
def test_truncate_to_budget_stops_once_budget_exceeded() -> None:
    builder = ConversationContextBuilder(max_chars=10)
    items = [
        _item("a", 0.9, text="12345"),
        _item("b", 0.8, text="12345"),
        _item("c", 0.7, text="12345"),
    ]
    selected, truncated = builder.truncate_to_budget(items)
    assert [item.source_id for item in selected] == ["a", "b"]
    assert truncated is True


@pytest.mark.unit
def test_assemble_reports_total_candidates_and_no_truncation_when_within_budget() -> None:
    builder = ConversationContextBuilder(max_chars=1_000)
    items = [_item("a", 0.9, text="alpha"), _item("b", 0.5, text="beta")]
    assembled = builder.assemble(items)
    assert assembled.total_candidates == 2
    assert assembled.truncated is False
    assert len(assembled.items) == 2
    assert assembled.duplicates_removed == 0


@pytest.mark.unit
def test_deduplicate_drops_exact_normalized_text_duplicate() -> None:
    builder = ConversationContextBuilder()
    items = [
        _item("a", 0.9, text="Brute force from 203.0.113.5"),
        _item("b", 0.5, text="brute   force from 203.0.113.5"),
    ]
    deduplicated, removed = builder.deduplicate(items)
    assert [item.source_id for item in deduplicated] == ["a"]
    assert removed == 1


@pytest.mark.unit
def test_deduplicate_keeps_distinct_text() -> None:
    builder = ConversationContextBuilder()
    items = [_item("a", 0.9, text="alpha"), _item("b", 0.5, text="beta")]
    deduplicated, removed = builder.deduplicate(items)
    assert len(deduplicated) == 2
    assert removed == 0


@pytest.mark.unit
def test_assemble_reports_duplicates_removed_count() -> None:
    builder = ConversationContextBuilder(max_chars=1_000)
    items = [
        _item("a", 0.9, text="same text"),
        _item("b", 0.5, text="same text"),
        _item("c", 0.3, text="different"),
    ]
    assembled = builder.assemble(items)
    assert assembled.duplicates_removed == 1
    assert [item.source_id for item in assembled.items] == ["a", "c"]
