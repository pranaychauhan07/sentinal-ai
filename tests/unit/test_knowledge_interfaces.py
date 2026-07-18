"""Structural-conformance tests for the knowledge Protocols — no concrete
knowledge source exists yet (abstraction only, per ADR-0010's scope)."""

from __future__ import annotations

import pytest

from core.knowledge.interfaces import KnowledgeRetriever, KnowledgeSource
from core.knowledge.models import KnowledgeDocument, KnowledgeQuery, KnowledgeSearchResult

pytestmark = pytest.mark.unit


class _FakeSource:
    source_type = "mitre_attack"

    def get(self, document_id: str) -> KnowledgeDocument | None:
        return None

    def search(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        return []


class _FakeRetriever:
    def retrieve(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        return []


def test_fake_source_satisfies_knowledge_source_protocol() -> None:
    assert isinstance(_FakeSource(), KnowledgeSource)


def test_fake_retriever_satisfies_knowledge_retriever_protocol() -> None:
    assert isinstance(_FakeRetriever(), KnowledgeRetriever)


def test_knowledge_source_protocol_is_importable_without_a_backing_class() -> None:
    assert KnowledgeSource.__mro__
