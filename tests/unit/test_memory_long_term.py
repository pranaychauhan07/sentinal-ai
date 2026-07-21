"""Unit tests for core/memory/long_term.py."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from core.memory.interfaces import LongTermMemory, SimilarResult
from core.memory.long_term import LongTermMemoryManager
from core.memory.vector_store import HashingTextEmbedder, InMemoryVectorStore

pytestmark = pytest.mark.unit


class _FailingVectorStore:
    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None:
        raise RuntimeError("backend unreachable")

    async def upsert_embeddings_batch(self, entries: Any) -> None:
        raise RuntimeError("backend unreachable")

    async def query_embedding(
        self,
        embedding: list[float],
        *,
        limit: int = 5,
        case_id: Any = None,
        metadata_filter: Any = None,
    ) -> list[SimilarResult]:
        raise RuntimeError("backend unreachable")

    async def delete(self, id: str) -> None:
        raise RuntimeError("backend unreachable")

    async def delete_case(self, case_id: Any) -> None:
        raise RuntimeError("backend unreachable")


def _manager(store: Any = None) -> LongTermMemoryManager:
    return LongTermMemoryManager(
        vector_store=store or InMemoryVectorStore(), embedder=HashingTextEmbedder()
    )


async def test_long_term_memory_manager_satisfies_protocol() -> None:
    assert isinstance(_manager(), LongTermMemory)


async def test_record_then_find_similar_round_trips() -> None:
    manager = _manager()
    case_id, finding_id = uuid4(), uuid4()
    await manager.record(case_id, finding_id, "repeated failed ssh logins from one IP")

    results = await manager.find_similar("failed ssh login attempts")
    assert len(results) == 1
    assert results[0].case_id == case_id
    assert results[0].finding_id == finding_id


async def test_find_similar_with_no_recorded_findings_is_empty() -> None:
    manager = _manager()
    assert await manager.find_similar("anything") == []


async def test_find_similar_degrades_to_empty_on_backend_failure() -> None:
    manager = _manager(_FailingVectorStore())
    assert await manager.find_similar("query") == []


async def test_record_degrades_silently_on_backend_failure() -> None:
    manager = _manager(_FailingVectorStore())
    # Must not raise — long-term memory is always advisory (ADR-0006).
    await manager.record(uuid4(), uuid4(), "content")


async def test_record_defaults_to_finding_category() -> None:
    manager = _manager()
    case_id, finding_id = uuid4(), uuid4()
    await manager.record(case_id, finding_id, "some finding text")
    results = await manager.find_similar("finding text")
    assert results[0].category == "finding"


async def test_record_with_explicit_category() -> None:
    manager = _manager()
    case_id, report_id = uuid4(), uuid4()
    await manager.record(case_id, report_id, "technical report summary", category="report")
    results = await manager.find_similar("technical report")
    assert results[0].category == "report"


async def test_find_similar_in_case_scopes_to_case() -> None:
    manager = _manager()
    case_a, case_b = uuid4(), uuid4()
    await manager.record(case_a, uuid4(), "brute force ssh login")
    await manager.record(case_b, uuid4(), "brute force ssh login")

    results = await manager.find_similar_in_case("brute force ssh", case_id=case_a)
    assert len(results) == 1
    assert results[0].case_id == case_a


async def test_find_similar_in_case_degrades_to_empty_on_backend_failure() -> None:
    manager = _manager(_FailingVectorStore())
    assert await manager.find_similar_in_case("query", case_id=uuid4()) == []


async def test_find_similar_excluding_case_drops_the_asking_case() -> None:
    manager = _manager()
    case_a, case_b = uuid4(), uuid4()
    await manager.record(case_a, uuid4(), "phishing email from external sender")
    await manager.record(case_b, uuid4(), "phishing email from external sender")

    results = await manager.find_similar_excluding_case(
        "phishing email external sender", exclude_case_id=case_a
    )
    assert len(results) == 1
    assert results[0].case_id == case_b


async def test_find_similar_excluding_case_by_category() -> None:
    manager = _manager()
    case_a, case_b = uuid4(), uuid4()
    await manager.record(case_a, uuid4(), "shared subject text", category="finding")
    await manager.record(case_b, uuid4(), "shared subject text", category="ioc")

    results = await manager.find_similar_excluding_case(
        "shared subject text", exclude_case_id=case_a, category="ioc"
    )
    assert len(results) == 1
    assert results[0].category == "ioc"


async def test_find_similar_excluding_case_degrades_to_empty_on_backend_failure() -> None:
    manager = _manager(_FailingVectorStore())
    assert await manager.find_similar_excluding_case("query", exclude_case_id=uuid4()) == []


async def test_delete_case_removes_recorded_vectors() -> None:
    manager = _manager()
    case_id = uuid4()
    await manager.record(case_id, uuid4(), "some content")
    await manager.delete_case(case_id)
    assert await manager.find_similar("some content") == []


async def test_delete_case_degrades_silently_on_backend_failure() -> None:
    manager = _manager(_FailingVectorStore())
    # Must not raise — advisory boundary, same as every other method here.
    await manager.delete_case(uuid4())


async def test_metrics_record_embedding_and_vector_store_calls() -> None:
    manager = _manager()
    await manager.record(uuid4(), uuid4(), "content")
    await manager.find_similar("content")
    snapshot = manager.metrics.snapshot()
    assert snapshot.embedding_calls == 2
    assert snapshot.vector_store_calls == 2
    assert snapshot.embedding_failures == 0


async def test_metrics_record_failure_on_embedding_error() -> None:
    class _FailingEmbedder:
        def embed(self, text: str) -> list[float]:
            raise RuntimeError("embedding provider down")

    manager = LongTermMemoryManager(vector_store=InMemoryVectorStore(), embedder=_FailingEmbedder())
    await manager.find_similar("query")
    assert manager.metrics.snapshot().embedding_failures == 1
