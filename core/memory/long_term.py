"""`LongTermMemoryManager` — the first concrete `LongTermMemory`
(`core/memory/interfaces.py`) implementation.

Wraps an injected `VectorMemory` (default `NullVectorStore`, see
`vector_store.py`) and a `TextEmbedder`. Per ADR-0006, long-term memory is
*always advisory* — every method here catches backend failures and degrades
to "no historical context" (an empty result / a logged, swallowed write
failure) rather than raising, so a vector-store outage never blocks an
investigation. Accessed only through a future Memory Agent per constitution
§4.4; this class itself has no opinion on who calls it.
"""

from __future__ import annotations

from uuid import UUID

from core.logging import get_logger
from core.memory.interfaces import SimilarResult, VectorMemory
from core.memory.vector_store import TextEmbedder

_logger = get_logger(__name__)


class LongTermMemoryManager:
    """Concrete `LongTermMemory`, backend-agnostic over `VectorMemory`."""

    def __init__(self, *, vector_store: VectorMemory, embedder: TextEmbedder) -> None:
        self._vector_store = vector_store
        self._embedder = embedder

    async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]:
        try:
            embedding = self._embedder.embed(query)
            return await self._vector_store.query_embedding(embedding, limit=limit)
        except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
            _logger.error("long_term_memory_query_failed", error=str(exc))
            return []

    async def record(self, case_id: UUID, finding_id: UUID, content: str) -> None:
        try:
            embedding = self._embedder.embed(content)
            await self._vector_store.upsert_embedding(
                id=f"{case_id}:{finding_id}",
                embedding=embedding,
                metadata={
                    "case_id": str(case_id),
                    "finding_id": str(finding_id),
                    "excerpt": content[:280],
                },
            )
        except Exception as exc:  # noqa: BLE001 - advisory boundary: a write failure degrades, never raises
            _logger.error(
                "long_term_memory_record_failed",
                case_id=str(case_id),
                finding_id=str(finding_id),
                error=str(exc),
            )
