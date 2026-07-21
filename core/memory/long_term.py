"""`LongTermMemoryManager` — the first concrete `LongTermMemory`
(`core/memory/interfaces.py`) implementation.

Wraps an injected `VectorMemory` (default `NullVectorStore`, see
`vector_store.py`) and a `TextEmbedder`. Per ADR-0006, long-term memory is
*always advisory* — every method here catches backend failures and degrades
to "no historical context" (an empty result / a logged, swallowed write
failure) rather than raising, so a vector-store outage never blocks an
investigation.

ADR-0027 extends this with a `category` tag on every recorded item
("finding"/"ioc"/"mitre_technique"/"report"/"case_summary") plus case-scoped
and cross-case ("similar past investigations") retrieval — the concrete
answer to blueprint §7's "has this IOC/pattern appeared in a past case?" for
the categories `core/services/case_service.py` writes on investigation
completion and `core/services/conversation_service.py` reads from the AI
Analyst Chat. Accessed only through `core/services` (no `core/agents`
specialist queries this directly, per constitution §4.4 — there is still no
graph-integrated Memory Agent, see ADR-0027's "Alternatives Considered").
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from core.logging import get_logger
from core.memory.interfaces import SimilarResult, VectorMemory
from core.memory.metrics import MemoryMetricsCollector
from core.memory.vector_store import TextEmbedder

_logger = get_logger(__name__)

#: Closed set of tags `record()` accepts — a plain string (not a `StrEnum`)
#: because it is stored as opaque vector-store metadata, never branched on
#: internally; kept here as the single documented source of valid values.
RECORD_CATEGORIES = ("finding", "ioc", "mitre_technique", "report", "case_summary")


class LongTermMemoryManager:
    """Concrete `LongTermMemory`, backend-agnostic over `VectorMemory`."""

    def __init__(
        self,
        *,
        vector_store: VectorMemory,
        embedder: TextEmbedder,
        metrics: MemoryMetricsCollector | None = None,
    ) -> None:
        self._vector_store = vector_store
        self._embedder = embedder
        #: ADR-0027 — separate embedding-call/vector-store-call timing from
        #: `MemoryManager`'s coarser `time_retrieval()` (which only times the
        #: whole `find_similar*` call). Constructed fresh per instance
        #: (constitution §2, "avoid global state"); a caller sharing one
        #: `MemoryManager` can pass its own collector in to aggregate.
        self.metrics = metrics or MemoryMetricsCollector()

    def _embed(self, text: str) -> list[float]:
        with self.metrics.time_embedding_call():
            return self._embedder.embed(text)

    async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]:
        """Cross-case by default (no `case_id` filter) — the original,
        unchanged behavior every existing caller depends on."""
        try:
            embedding = self._embed(query)
            with self.metrics.time_vector_store_call():
                return await self._vector_store.query_embedding(embedding, limit=limit)
        except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
            _logger.error("long_term_memory_query_failed", error=str(exc))
            return []

    async def find_similar_in_case(
        self, query: str, *, case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        """Case-scoped retrieval — "what in *this* case already resembles
        this question/finding?" """
        try:
            embedding = self._embed(query)
            with self.metrics.time_vector_store_call():
                return await self._vector_store.query_embedding(
                    embedding, limit=limit, case_id=case_id
                )
        except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
            _logger.error("long_term_memory_query_failed", case_id=str(case_id), error=str(exc))
            return []

    async def find_similar_excluding_case(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5, category: str | None = None
    ) -> list[SimilarResult]:
        """ "Similar past investigations" — cross-case retrieval that drops
        matches from the case asking the question, optionally narrowed to
        one `category`. Chroma has no native "not equal" filter in this
        project's usage, so this over-fetches and filters client-side —
        acceptable at this project's case volume (constitution §5,
        "caching"/perf notes apply to genuinely expensive lookups; this is
        not one)."""
        try:
            embedding = self._embed(query)
            metadata_filter = {"category": category} if category else None
            with self.metrics.time_vector_store_call():
                candidates = await self._vector_store.query_embedding(
                    embedding, limit=limit * 3, metadata_filter=metadata_filter
                )
            return [r for r in candidates if r.case_id != exclude_case_id][:limit]
        except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
            _logger.error(
                "long_term_memory_query_failed",
                exclude_case_id=str(exclude_case_id),
                error=str(exc),
            )
            return []

    async def find_similar_findings(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        return await self.find_similar_excluding_case(
            query, exclude_case_id=exclude_case_id, limit=limit, category="finding"
        )

    async def find_similar_iocs(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        return await self.find_similar_excluding_case(
            query, exclude_case_id=exclude_case_id, limit=limit, category="ioc"
        )

    async def find_similar_mitre_techniques(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        return await self.find_similar_excluding_case(
            query, exclude_case_id=exclude_case_id, limit=limit, category="mitre_technique"
        )

    async def find_similar_reports(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        return await self.find_similar_excluding_case(
            query, exclude_case_id=exclude_case_id, limit=limit, category="report"
        )

    async def find_similar_cases(
        self, query: str, *, exclude_case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        return await self.find_similar_excluding_case(
            query, exclude_case_id=exclude_case_id, limit=limit, category="case_summary"
        )

    async def record(
        self, case_id: UUID, finding_id: UUID, content: str, *, category: str = "finding"
    ) -> None:
        try:
            embedding = self._embed(content)
            with self.metrics.time_vector_store_call():
                await self._vector_store.upsert_embedding(
                    id=f"{case_id}:{finding_id}",
                    embedding=embedding,
                    metadata={
                        "case_id": str(case_id),
                        "finding_id": str(finding_id),
                        "excerpt": content[:280],
                        "category": category,
                        # ADR-0028: recorded so `SimilarResult.recorded_at` can
                        # surface "how old is this match" to a retrieval
                        # consumer (the Memory Agent) without a separate
                        # lookup.
                        "recorded_at": datetime.now(UTC).isoformat(),
                    },
                )
        except Exception as exc:  # noqa: BLE001 - advisory boundary: a write failure degrades, never raises
            _logger.error(
                "long_term_memory_record_failed",
                case_id=str(case_id),
                finding_id=str(finding_id),
                error=str(exc),
            )

    async def delete_case(self, case_id: UUID) -> None:
        """Removes every vector recorded for `case_id` — used when a case
        is deleted, so stale embeddings never surface in a future cross-case
        search. Advisory like every other method here: a failure is logged,
        never raised."""
        try:
            with self.metrics.time_vector_store_call():
                await self._vector_store.delete_case(case_id)
        except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
            _logger.error(
                "long_term_memory_delete_case_failed", case_id=str(case_id), error=str(exc)
            )
