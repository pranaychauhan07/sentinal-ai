"""Concrete implementations of `VectorMemory` (`core/memory/interfaces.py`).

Per ADR-0027, the real production backend is now `core/memory/
chroma_vector_store.py`. This module keeps `InMemoryVectorStore`/
`NullVectorStore` as genuinely useful, dependency-free reference
implementations of the same (now-extended) Protocol — fast for tests, usable
for local dev without a Chroma install, and the documented no-op fallback
demonstrating the "memory retrieval is always advisory" contract (ADR-0006) at
the storage boundary itself. Neither is a stand-in that "will be replaced out
of necessity"; both remain first-class, tested implementations.

Per docs/dependency-rules.md rule 6, only `chroma_vector_store.py` (within
`core/memory`) imports a real vector-store client — the implementations below
have no such client, by design.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from core.memory.interfaces import SimilarResult, VectorEntry


@runtime_checkable
class TextEmbedder(Protocol):
    """Contract for turning text into a vector.

    `long_term.py` depends on this, not on any specific embedding provider.
    `core/memory/embedding_providers.py` (ADR-0027) supplies the real
    OpenAI/Gemini/Ollama-backed implementations, selected via
    `core/config/settings.py`'s `LLMProvider`; `HashingTextEmbedder` below
    remains the deterministic, dependency-free default/fallback. Kept
    narrow (one method) so it's trivially fakeable in tests.
    """

    def embed(self, text: str) -> list[float]: ...


class HashingTextEmbedder:
    """Deterministic, dependency-free `TextEmbedder` using the feature-hashing
    trick (hash each token into one of `dimensions` buckets, count
    occurrences, L2-normalize).

    Not a semantic embedding — two paraphrased sentences with different
    words will not score as similar. It exists so `LongTermMemory` and
    `InMemoryVectorStore` are exercisable end-to-end without an LLM provider
    call in the loop (constitution Principle 9: deterministic where
    possible). A real semantic embedder (LLM-provider-backed) is the
    intended production swap, satisfying the same `TextEmbedder` Protocol.
    """

    def __init__(self, dimensions: int = 64) -> None:
        self.dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in text.lower().split():
            # `hashlib` (not the builtin `hash()`) so the result is stable
            # across processes/runs — `hash()` is salted per-process
            # (PYTHONHASHSEED) for security and would make this "deterministic"
            # embedder non-deterministic across restarts.
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:8], "big") % self.dimensions
            vector[bucket] += 1.0
        norm = math.sqrt(sum(component * component for component in vector))
        if norm == 0.0:
            return vector
        return [component / norm for component in vector]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


class InMemoryVectorStore:
    """Brute-force, O(n) cosine-similarity `VectorMemory`.

    Genuinely functional (not a stub): exact same ranking semantics a real
    vector database provides, just without the indexing that makes one fast
    at scale. Appropriate for tests, local dev, and small case volumes;
    explicitly not a substitute for ChromaDB at production scale — see
    ADR-0010's "Consequences" section.
    """

    def __init__(self) -> None:
        self._vectors: dict[str, list[float]] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None:
        self._vectors[id] = list(embedding)
        self._metadata[id] = dict(metadata)

    async def upsert_embeddings_batch(self, entries: Sequence[VectorEntry]) -> None:
        for entry in entries:
            await self.upsert_embedding(
                id=entry.id, embedding=entry.embedding, metadata=entry.metadata
            )

    async def query_embedding(
        self,
        embedding: list[float],
        *,
        limit: int = 5,
        case_id: UUID | None = None,
        metadata_filter: dict[str, str] | None = None,
    ) -> list[SimilarResult]:
        candidate_ids = (
            entry_id
            for entry_id, metadata in self._metadata.items()
            if self._matches_filter(metadata, case_id=case_id, metadata_filter=metadata_filter)
        )
        scored = [
            (entry_id, _cosine_similarity(embedding, self._vectors[entry_id]))
            for entry_id in candidate_ids
        ]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        results: list[SimilarResult] = []
        for entry_id, score in scored[:limit]:
            metadata = self._metadata.get(entry_id, {})
            results.append(
                SimilarResult(
                    case_id=UUID(str(metadata.get("case_id"))),
                    finding_id=UUID(str(metadata.get("finding_id"))),
                    score=max(0.0, min(1.0, score)),
                    excerpt=str(metadata.get("excerpt", "")),
                    category=str(metadata.get("category", "finding")),
                )
            )
        return results

    async def delete(self, id: str) -> None:
        self._vectors.pop(id, None)
        self._metadata.pop(id, None)

    async def delete_case(self, case_id: UUID) -> None:
        stale_ids = [
            entry_id
            for entry_id, metadata in self._metadata.items()
            if str(metadata.get("case_id")) == str(case_id)
        ]
        for entry_id in stale_ids:
            await self.delete(entry_id)

    def size(self) -> int:
        return len(self._vectors)

    @staticmethod
    def _matches_filter(
        metadata: dict[str, Any],
        *,
        case_id: UUID | None,
        metadata_filter: dict[str, str] | None,
    ) -> bool:
        if case_id is not None and str(metadata.get("case_id")) != str(case_id):
            return False
        if metadata_filter:
            for key, value in metadata_filter.items():
                if str(metadata.get(key)) != value:
                    return False
        return True


class NullVectorStore:
    """No-op `VectorMemory` — the explicit, documented fallback used when no
    real backend is configured (constitution §7, "Fail gracefully": long-term
    memory degrades to 'no historical context', never a hard failure, per
    ADR-0006)."""

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None:
        return None

    async def upsert_embeddings_batch(self, entries: Sequence[VectorEntry]) -> None:
        return None

    async def query_embedding(
        self,
        embedding: list[float],
        *,
        limit: int = 5,
        case_id: UUID | None = None,
        metadata_filter: dict[str, str] | None = None,
    ) -> list[SimilarResult]:
        return []

    async def delete(self, id: str) -> None:
        return None

    async def delete_case(self, case_id: UUID) -> None:
        return None
