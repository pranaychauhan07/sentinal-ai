"""Unit tests for core/memory/investigation_context.py — the Memory Agent's
"Memory Service" (ADR-0028): ranking, confidence-thresholding, per-category
top-K truncation, cross-call deduplication, and advisory failure handling."""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.memory.interfaces import SimilarResult
from core.memory.investigation_context import (
    MemoryRetrievalConfig,
    build_investigation_memory_context,
)
from core.memory.long_term import LongTermMemoryManager
from core.memory.vector_store import HashingTextEmbedder, InMemoryVectorStore

pytestmark = pytest.mark.unit


def _manager() -> LongTermMemoryManager:
    return LongTermMemoryManager(vector_store=InMemoryVectorStore(), embedder=HashingTextEmbedder())


async def test_empty_query_text_short_circuits_without_calling_backend() -> None:
    manager = _manager()
    result = await build_investigation_memory_context(
        "   ", case_id=uuid4(), long_term_memory=manager
    )
    assert result.degraded is True
    assert result.outcomes == ()


async def test_queries_every_default_category() -> None:
    manager = _manager()
    result = await build_investigation_memory_context(
        "brute force ssh login", case_id=uuid4(), long_term_memory=manager
    )
    categories = {outcome.category for outcome in result.outcomes}
    assert categories == {"case_summary", "finding", "ioc", "mitre_technique", "report"}


async def test_finds_a_recorded_similar_finding_from_another_case() -> None:
    manager = _manager()
    other_case = uuid4()
    await manager.record(
        other_case, uuid4(), "repeated failed ssh logins from one IP", category="finding"
    )

    result = await build_investigation_memory_context(
        "repeated failed ssh logins from one IP", case_id=uuid4(), long_term_memory=manager
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert len(outcome.results) == 1
    assert outcome.results[0].case_id == other_case


async def test_excludes_matches_from_the_asking_case() -> None:
    manager = _manager()
    case_id = uuid4()
    await manager.record(case_id, uuid4(), "shared ssh brute force signal", category="finding")

    result = await build_investigation_memory_context(
        "shared ssh brute force signal", case_id=case_id, long_term_memory=manager
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert outcome.results == ()


async def test_min_similarity_threshold_drops_weak_matches() -> None:
    manager = _manager()
    await manager.record(
        uuid4(), uuid4(), "completely unrelated text about weather", category="finding"
    )

    config = MemoryRetrievalConfig(categories=("finding",), min_similarity=0.99)
    result = await build_investigation_memory_context(
        "brute force ssh login attempt", case_id=uuid4(), long_term_memory=manager, config=config
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert outcome.results == ()
    assert outcome.below_threshold_dropped >= 1


async def test_top_k_per_category_truncates() -> None:
    manager = _manager()
    for i in range(10):
        await manager.record(
            uuid4(), uuid4(), f"brute force ssh login attempt variant {i}", category="finding"
        )

    config = MemoryRetrievalConfig(
        categories=("finding",), top_k_per_category=3, min_similarity=0.0
    )
    result = await build_investigation_memory_context(
        "brute force ssh login attempt", case_id=uuid4(), long_term_memory=manager, config=config
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert len(outcome.results) == 3


async def test_deduplicates_the_same_case_finding_pair_across_ranking() -> None:
    """A backend that returns the same (case_id, finding_id) pair twice
    (a defensive scenario `LongTermMemoryManager` itself never produces,
    but this module must not assume otherwise) is deduplicated, keeping the
    highest-scored occurrence."""

    class _DuplicatingLongTermMemory:
        def __init__(self, duplicate: SimilarResult) -> None:
            self._duplicate = duplicate

        async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]:
            return []

        async def find_similar_in_case(
            self, query: str, *, case_id, limit: int = 5
        ) -> list[SimilarResult]:
            return []

        async def find_similar_excluding_case(
            self, query: str, *, exclude_case_id, limit: int = 5, category: str | None = None
        ) -> list[SimilarResult]:
            if category != "finding":
                return []
            return [self._duplicate, self._duplicate]

        async def record(
            self, case_id, finding_id, content: str, *, category: str = "finding"
        ) -> None:
            return None

        async def delete_case(self, case_id) -> None:
            return None

    duplicate = SimilarResult(
        case_id=uuid4(), finding_id=uuid4(), score=0.9, excerpt="dup", category="finding"
    )
    config = MemoryRetrievalConfig(categories=("finding",))
    result = await build_investigation_memory_context(
        "query",
        case_id=uuid4(),
        long_term_memory=_DuplicatingLongTermMemory(duplicate),
        config=config,
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert len(outcome.results) == 1
    assert outcome.duplicate_dropped == 1


async def test_one_category_failing_never_blocks_the_others() -> None:
    class _PartiallyFailingLongTermMemory:
        async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]:
            return []

        async def find_similar_in_case(
            self, query: str, *, case_id, limit: int = 5
        ) -> list[SimilarResult]:
            return []

        async def find_similar_excluding_case(
            self, query: str, *, exclude_case_id, limit: int = 5, category: str | None = None
        ) -> list[SimilarResult]:
            if category == "ioc":
                raise RuntimeError("backend unreachable")
            return [
                SimilarResult(
                    case_id=uuid4(),
                    finding_id=uuid4(),
                    score=0.8,
                    excerpt="ok",
                    category=category or "",
                )
            ]

        async def record(
            self, case_id, finding_id, content: str, *, category: str = "finding"
        ) -> None:
            return None

        async def delete_case(self, case_id) -> None:
            return None

    result = await build_investigation_memory_context(
        "query", case_id=uuid4(), long_term_memory=_PartiallyFailingLongTermMemory()
    )
    ioc_outcome = result.outcome_for("ioc")
    finding_outcome = result.outcome_for("finding")
    assert ioc_outcome is not None
    assert ioc_outcome.degraded is True
    assert ioc_outcome.error is not None
    assert finding_outcome is not None
    assert finding_outcome.degraded is False
    assert len(finding_outcome.results) == 1
    assert result.degraded is True


async def test_large_collection_still_respects_top_k() -> None:
    """A large recorded history for one category doesn't balloon the
    returned result set — the top-K guard holds under volume."""
    manager = _manager()
    for i in range(200):
        await manager.record(
            uuid4(), uuid4(), f"brute force login attempt number {i}", category="finding"
        )

    config = MemoryRetrievalConfig(
        categories=("finding",), top_k_per_category=5, min_similarity=0.0
    )
    result = await build_investigation_memory_context(
        "brute force login attempt", case_id=uuid4(), long_term_memory=manager, config=config
    )
    outcome = result.outcome_for("finding")
    assert outcome is not None
    assert len(outcome.results) == 5
    assert outcome.raw_candidate_count >= 5
