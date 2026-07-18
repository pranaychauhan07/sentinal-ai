"""Unit tests for core/knowledge/models.py."""

from __future__ import annotations

import pytest

from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)

pytestmark = pytest.mark.unit


def test_knowledge_document_is_frozen() -> None:
    doc = KnowledgeDocument(
        id="T1110",
        source_type=KnowledgeSourceType.MITRE_ATTACK,
        title="Brute Force",
        content="Adversaries may use brute force techniques.",
    )
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic frozen-instance error
        doc.title = "changed"  # type: ignore[misc]


def test_knowledge_query_defaults() -> None:
    query = KnowledgeQuery(text="brute force")
    assert query.limit == 10
    assert query.source_types == ()


def test_knowledge_search_result_score_is_bounded() -> None:
    doc = KnowledgeDocument(
        id="A01",
        source_type=KnowledgeSourceType.OWASP_TOP10,
        title="Broken Access Control",
        content="...",
    )
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic validation error
        KnowledgeSearchResult(document=doc, score=1.5)
