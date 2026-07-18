"""Structural contracts every knowledge source / retriever satisfies.

Pure `typing.Protocol` — no implementation, no data. A future
`MitreAttackSource` (loading `core/knowledge/mitre_attack.json`, per
`core/knowledge/README.md`) or `OwaspTop10Source` implements
`KnowledgeSource`; a future RAG pipeline implements `KnowledgeRetriever`.
Neither is built here (ADR-0010, explicit scope: infrastructure only).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.knowledge.models import KnowledgeDocument, KnowledgeQuery, KnowledgeSearchResult


@runtime_checkable
class KnowledgeSource(Protocol):
    """Contract for one taxonomy/dataset (MITRE, OWASP, a playbook set, ...).

    `source_type` identifies which `KnowledgeSourceType` this instance
    serves — a `KnowledgeSourceRegistry` (`registry.py`) uses it as the
    registration key.
    """

    source_type: str

    def get(self, document_id: str) -> KnowledgeDocument | None: ...

    def search(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]: ...


@runtime_checkable
class KnowledgeRetriever(Protocol):
    """Contract for a retrieval strategy operating across one or more
    registered `KnowledgeSource`s — the seam a future RAG/embedding-based
    pipeline plugs into without changing any agent that already depends on
    this Protocol (same "swap the backend, not the caller" pattern as
    `core.memory.interfaces.VectorMemory`)."""

    def retrieve(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]: ...
