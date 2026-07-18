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

    async def query_embedding(
        self, embedding: list[float], *, limit: int = 5
    ) -> list[SimilarResult]:
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
