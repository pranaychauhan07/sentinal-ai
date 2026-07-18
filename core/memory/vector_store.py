"""Concrete implementations of `VectorMemory` (`core/memory/interfaces.py`).

Per ADR-0010 and ADR-0005, ChromaDB remains the M6 production backend — not
built here. This module gives `long_term.py` (and its tests) a genuinely
working, in-process reference implementation of the same Protocol today, so
the rest of the memory layer isn't blocked on M6, plus a documented no-op
fallback demonstrating the "memory retrieval is always advisory" contract
(ADR-0006) at the storage boundary itself.

Per docs/dependency-rules.md rule 6, only this module (within `core/memory`)
would ever import a real vector-store client — the in-memory implementation
below has no such client, by design.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from core.memory.interfaces import SimilarResult


@runtime_checkable
class TextEmbedder(Protocol):
    """Contract for turning text into a fixed-dimension vector.

    `long_term.py` depends on this, not on any specific embedding provider —
    a future LLM-provider-backed embedder (OpenAI/Gemini/Ollama, per
    `core/config/settings.py`'s `LLMProvider`) is a drop-in swap. Kept
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

    async def query_embedding(
        self, embedding: list[float], *, limit: int = 5
    ) -> list[SimilarResult]:
        scored = [
            (entry_id, _cosine_similarity(embedding, vector))
            for entry_id, vector in self._vectors.items()
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
                )
            )
        return results

    def size(self) -> int:
        return len(self._vectors)


class NullVectorStore:
    """No-op `VectorMemory` — the explicit, documented fallback used when no
    real backend is configured (constitution §7, "Fail gracefully": long-term
    memory degrades to 'no historical context', never a hard failure, per
    ADR-0006)."""

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None:
        return None

    async def query_embedding(
        self, embedding: list[float], *, limit: int = 5
    ) -> list[SimilarResult]:
        return []
