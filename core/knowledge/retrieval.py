"""`KeywordKnowledgeRetriever` — the one concrete `KnowledgeRetriever`
(`core/knowledge/interfaces.py`) this milestone ships.

Deterministic keyword/substring scoring across every registered
`KnowledgeSource` (constitution Principle 9: retrieval ranking is a plain
function, not an LLM guess). This is deliberately *not* semantic/RAG
retrieval — a future embedding-based `KnowledgeRetriever` (blueprint §4,
"Future RAG integration") satisfies the same Protocol and is a swap-in
replacement, not a rewrite of any caller.
"""

from __future__ import annotations

from core.knowledge.models import KnowledgeQuery, KnowledgeSearchResult
from core.knowledge.registry import KnowledgeSourceRegistry


class KeywordKnowledgeRetriever:
    """Scores each candidate document by the fraction of query tokens found
    in its title/content, querying every source the caller asked for (or all
    registered sources if `query.source_types` is empty)."""

    def __init__(self, registry: KnowledgeSourceRegistry) -> None:
        self._registry = registry

    def retrieve(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        sources = (
            [self._registry.get(source_type) for source_type in query.source_types]
            if query.source_types
            else list(self._registry.all_sources())
        )

        results: list[KnowledgeSearchResult] = []
        for source in sources:
            results.extend(source.search(query))

        results.sort(key=lambda result: result.score, reverse=True)
        return results[: query.limit]

    @staticmethod
    def score_text(query_text: str, candidate_text: str) -> float:
        """Fraction of distinct query tokens present in `candidate_text`
        (case-insensitive). Exposed as a `staticmethod` so a concrete
        `KnowledgeSource.search()` implementation can reuse the exact same
        scoring function rather than reinventing keyword matching
        per-source (constitution §14, "never duplicate functionality")."""
        query_tokens = {token for token in query_text.lower().split() if token}
        if not query_tokens:
            return 0.0
        candidate_lower = candidate_text.lower()
        matched = sum(1 for token in query_tokens if token in candidate_lower)
        return matched / len(query_tokens)
