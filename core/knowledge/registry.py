"""`KnowledgeSourceRegistry` — where concrete `KnowledgeSource` instances
register themselves, mirroring `core.agents.registry.AgentRegistry`'s
pattern.

Empty at process start today: no MITRE/OWASP/threat-intel source exists yet
(ADR-0010 — this milestone is infrastructure only). A future
`MitreAttackSource`/`OwaspTop10Source` registers here by
`KnowledgeSourceType`, and `retrieval.py`'s retriever looks sources up
through this registry rather than importing them directly.
"""

from __future__ import annotations

from functools import lru_cache

from core.exceptions import NotFoundError
from core.knowledge.interfaces import KnowledgeSource
from core.knowledge.models import KnowledgeSourceType


class KnowledgeSourceRegistry:
    """An explicit, injectable registry (constitution §2, "avoid global
    state") — construct one per process (see
    :func:`default_knowledge_registry`) or one per test for isolation."""

    def __init__(self) -> None:
        self._sources: dict[KnowledgeSourceType, KnowledgeSource] = {}

    def register(self, source_type: KnowledgeSourceType, source: KnowledgeSource) -> None:
        self._sources[source_type] = source

    def get(self, source_type: KnowledgeSourceType) -> KnowledgeSource:
        try:
            return self._sources[source_type]
        except KeyError as exc:
            raise NotFoundError(
                f"No knowledge source registered for '{source_type.value}'.",
                details={
                    "source_type": source_type.value,
                    "available": sorted(s.value for s in self._sources),
                },
            ) from exc

    def has(self, source_type: KnowledgeSourceType) -> bool:
        return source_type in self._sources

    def list_source_types(self) -> tuple[KnowledgeSourceType, ...]:
        return tuple(sorted(self._sources, key=lambda s: s.value))

    def all_sources(self) -> tuple[KnowledgeSource, ...]:
        return tuple(self._sources[s] for s in self.list_source_types())

    def unregister(self, source_type: KnowledgeSourceType) -> None:
        self._sources.pop(source_type, None)


@lru_cache
def default_knowledge_registry() -> KnowledgeSourceRegistry:
    """Process-wide singleton, matching `default_agent_registry`/
    `default_tool_registry`. Empty until a concrete knowledge source is
    implemented and registers itself (later milestone, per
    `core/knowledge/README.md`)."""
    return KnowledgeSourceRegistry()
