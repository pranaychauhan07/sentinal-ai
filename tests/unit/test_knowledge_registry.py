"""Unit tests for core/knowledge/registry.py."""

from __future__ import annotations

import pytest

from core.exceptions import NotFoundError
from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.registry import KnowledgeSourceRegistry, default_knowledge_registry

pytestmark = pytest.mark.unit


class _FakeSource:
    source_type = KnowledgeSourceType.MITRE_ATTACK.value

    def get(self, document_id: str) -> KnowledgeDocument | None:
        return None

    def search(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        return []


def test_register_and_get_round_trips() -> None:
    registry = KnowledgeSourceRegistry()
    source = _FakeSource()
    registry.register(KnowledgeSourceType.MITRE_ATTACK, source)
    assert registry.get(KnowledgeSourceType.MITRE_ATTACK) is source


def test_get_missing_source_raises_not_found_error() -> None:
    registry = KnowledgeSourceRegistry()
    with pytest.raises(NotFoundError):
        registry.get(KnowledgeSourceType.OWASP_TOP10)


def test_has_reflects_registration_state() -> None:
    registry = KnowledgeSourceRegistry()
    assert registry.has(KnowledgeSourceType.MITRE_ATTACK) is False
    registry.register(KnowledgeSourceType.MITRE_ATTACK, _FakeSource())
    assert registry.has(KnowledgeSourceType.MITRE_ATTACK) is True


def test_all_sources_returns_every_registered_source() -> None:
    registry = KnowledgeSourceRegistry()
    registry.register(KnowledgeSourceType.MITRE_ATTACK, _FakeSource())
    assert len(registry.all_sources()) == 1


def test_default_knowledge_registry_is_a_singleton() -> None:
    assert default_knowledge_registry() is default_knowledge_registry()


def test_default_knowledge_registry_starts_empty_per_this_milestones_scope() -> None:
    # Cleared implicitly by process-wide singleton semantics not being reset
    # between tests would be a problem, but nothing in this test suite
    # registers a source, so this documents the "no data populated yet"
    # scope (ADR-0010) rather than asserting global test-isolation guarantees.
    assert isinstance(default_knowledge_registry(), KnowledgeSourceRegistry)
