"""Unit tests for core/knowledge/retrieval.py."""

from __future__ import annotations

import pytest

from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.registry import KnowledgeSourceRegistry
from core.knowledge.retrieval import KeywordKnowledgeRetriever

pytestmark = pytest.mark.unit


class _StaticSource:
    def __init__(
        self, source_type: KnowledgeSourceType, documents: list[KnowledgeDocument]
    ) -> None:
        self.source_type = source_type.value
        self._documents = documents

    def get(self, document_id: str) -> KnowledgeDocument | None:
        return next((d for d in self._documents if d.id == document_id), None)

    def search(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        results = []
        for doc in self._documents:
            score = KeywordKnowledgeRetriever.score_text(query.text, f"{doc.title} {doc.content}")
            if score > 0:
                results.append(KnowledgeSearchResult(document=doc, score=score))
        return results


def _mitre_doc(doc_id: str, title: str, content: str) -> KnowledgeDocument:
    return KnowledgeDocument(
        id=doc_id, source_type=KnowledgeSourceType.MITRE_ATTACK, title=title, content=content
    )


def test_score_text_is_fraction_of_matched_tokens() -> None:
    score = KeywordKnowledgeRetriever.score_text("brute force login", "a brute force attempt")
    assert score == pytest.approx(2 / 3)


def test_score_text_empty_query_scores_zero() -> None:
    assert KeywordKnowledgeRetriever.score_text("", "anything") == 0.0


def test_retrieve_queries_all_registered_sources_when_unfiltered() -> None:
    registry = KnowledgeSourceRegistry()
    registry.register(
        KnowledgeSourceType.MITRE_ATTACK,
        _StaticSource(
            KnowledgeSourceType.MITRE_ATTACK,
            [_mitre_doc("T1110", "Brute Force", "repeated login attempts")],
        ),
    )
    retriever = KeywordKnowledgeRetriever(registry)

    results = retriever.retrieve(KnowledgeQuery(text="brute force"))
    assert len(results) == 1
    assert results[0].document.id == "T1110"


def test_retrieve_respects_limit_and_ranks_by_score() -> None:
    registry = KnowledgeSourceRegistry()
    registry.register(
        KnowledgeSourceType.MITRE_ATTACK,
        _StaticSource(
            KnowledgeSourceType.MITRE_ATTACK,
            [
                _mitre_doc("T1110", "Brute Force", "brute force login"),
                _mitre_doc("T1078", "Valid Accounts", "brute"),
            ],
        ),
    )
    retriever = KeywordKnowledgeRetriever(registry)

    results = retriever.retrieve(KnowledgeQuery(text="brute force login", limit=1))
    assert len(results) == 1
    assert results[0].document.id == "T1110"


def test_retrieve_can_be_restricted_to_specific_source_types() -> None:
    registry = KnowledgeSourceRegistry()
    registry.register(
        KnowledgeSourceType.MITRE_ATTACK,
        _StaticSource(
            KnowledgeSourceType.MITRE_ATTACK, [_mitre_doc("T1110", "Brute Force", "login")]
        ),
    )
    registry.register(
        KnowledgeSourceType.OWASP_TOP10,
        _StaticSource(
            KnowledgeSourceType.OWASP_TOP10,
            [
                KnowledgeDocument(
                    id="A07",
                    source_type=KnowledgeSourceType.OWASP_TOP10,
                    title="Identification and Authentication Failures",
                    content="login",
                )
            ],
        ),
    )
    retriever = KeywordKnowledgeRetriever(registry)

    results = retriever.retrieve(
        KnowledgeQuery(text="login", source_types=(KnowledgeSourceType.OWASP_TOP10,))
    )
    assert len(results) == 1
    assert results[0].document.source_type == KnowledgeSourceType.OWASP_TOP10
