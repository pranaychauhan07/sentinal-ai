"""Unit tests for core/conversation/citation_engine.py."""

from __future__ import annotations

import pytest

from core.conversation.citation_engine import CitationEngine
from core.conversation.models import (
    ChatCompletion,
    EvidenceCategory,
    RetrievedItem,
    SourceReference,
)


def _item(source_id: str) -> RetrievedItem:
    return RetrievedItem(
        category=EvidenceCategory.FINDING,
        source_id=source_id,
        text="t",
        relevance_score=0.5,
        reference=SourceReference(
            category=EvidenceCategory.FINDING, source_id=source_id, summary="s"
        ),
    )


@pytest.mark.unit
def test_cite_attaches_reference_for_used_source_id() -> None:
    engine = CitationEngine()
    completion = ChatCompletion(answer_text="a", used_source_ids=("f1",))
    citations = engine.cite(completion, available_items=[_item("f1")])
    assert len(citations) == 1
    assert citations[0].source_id == "f1"


@pytest.mark.unit
def test_cite_never_fabricates_a_citation_for_an_unavailable_source_id() -> None:
    engine = CitationEngine()
    completion = ChatCompletion(answer_text="a", used_source_ids=("does-not-exist",))
    citations = engine.cite(completion, available_items=[_item("f1")])
    assert citations == ()


@pytest.mark.unit
def test_cite_deduplicates_repeated_source_ids() -> None:
    engine = CitationEngine()
    completion = ChatCompletion(answer_text="a", used_source_ids=("f1", "f1"))
    citations = engine.cite(completion, available_items=[_item("f1")])
    assert len(citations) == 1
