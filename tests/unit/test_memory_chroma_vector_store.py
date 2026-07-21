"""Unit tests for core/memory/chroma_vector_store.py — against a real,
local, temp-directory ChromaDB (no server, no mocking needed: Chroma runs
fully in-process). Mirrors constitution §11's "mock at the boundary" rule
in spirit — there is no external boundary here to mock, this backend *is*
local.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.memory.chroma_vector_store import ChromaVectorStore
from core.memory.exceptions import InvalidEmbeddingError
from core.memory.interfaces import VectorEntry, VectorMemory

pytestmark = pytest.mark.unit


@pytest.fixture
def store(tmp_path: object) -> ChromaVectorStore:
    return ChromaVectorStore(persist_dir=str(tmp_path))


def test_satisfies_vector_memory_protocol(store: ChromaVectorStore) -> None:
    assert isinstance(store, VectorMemory)


async def test_upsert_then_query_round_trips(store: ChromaVectorStore) -> None:
    case_id, finding_id = uuid4(), uuid4()
    await store.upsert_embedding(
        id="a",
        embedding=[1.0, 0.0, 0.0],
        metadata={
            "case_id": str(case_id),
            "finding_id": str(finding_id),
            "excerpt": "brute force",
            "category": "finding",
        },
    )
    results = await store.query_embedding([1.0, 0.0, 0.0], limit=5)
    assert len(results) == 1
    assert results[0].case_id == case_id
    assert results[0].finding_id == finding_id
    assert results[0].excerpt == "brute force"
    assert results[0].category == "finding"
    assert results[0].score == pytest.approx(1.0, abs=1e-6)


async def test_batch_upsert(store: ChromaVectorStore) -> None:
    entries = [
        VectorEntry(
            id=str(i),
            embedding=[float(i), 1.0],
            metadata={"case_id": str(uuid4()), "finding_id": str(uuid4())},
        )
        for i in range(5)
    ]
    await store.upsert_embeddings_batch(entries)
    assert store.count() == 5


async def test_case_scoped_query_excludes_other_cases(store: ChromaVectorStore) -> None:
    case_a, case_b = uuid4(), uuid4()
    await store.upsert_embedding(
        id="a", embedding=[1.0, 0.0], metadata={"case_id": str(case_a), "finding_id": str(uuid4())}
    )
    await store.upsert_embedding(
        id="b", embedding=[1.0, 0.0], metadata={"case_id": str(case_b), "finding_id": str(uuid4())}
    )
    results = await store.query_embedding([1.0, 0.0], limit=5, case_id=case_a)
    assert len(results) == 1
    assert results[0].case_id == case_a


async def test_metadata_filter_query(store: ChromaVectorStore) -> None:
    await store.upsert_embedding(
        id="a",
        embedding=[1.0, 0.0],
        metadata={"case_id": str(uuid4()), "finding_id": str(uuid4()), "category": "ioc"},
    )
    await store.upsert_embedding(
        id="b",
        embedding=[1.0, 0.0],
        metadata={"case_id": str(uuid4()), "finding_id": str(uuid4()), "category": "finding"},
    )
    results = await store.query_embedding([1.0, 0.0], limit=5, metadata_filter={"category": "ioc"})
    assert len(results) == 1
    assert results[0].category == "ioc"


async def test_delete_removes_a_single_vector(store: ChromaVectorStore) -> None:
    await store.upsert_embedding(
        id="a", embedding=[1.0], metadata={"case_id": str(uuid4()), "finding_id": str(uuid4())}
    )
    await store.delete("a")
    assert store.count() == 0


async def test_delete_case_removes_every_vector_for_that_case(store: ChromaVectorStore) -> None:
    case_a, case_b = uuid4(), uuid4()
    await store.upsert_embedding(
        id="a", embedding=[1.0], metadata={"case_id": str(case_a), "finding_id": str(uuid4())}
    )
    await store.upsert_embedding(
        id="b", embedding=[1.0], metadata={"case_id": str(case_b), "finding_id": str(uuid4())}
    )
    await store.delete_case(case_a)
    assert store.count() == 1


async def test_upsert_rejects_empty_embedding(store: ChromaVectorStore) -> None:
    with pytest.raises(InvalidEmbeddingError):
        await store.upsert_embedding(id="a", embedding=[], metadata={})


async def test_upsert_rejects_non_finite_embedding(store: ChromaVectorStore) -> None:
    with pytest.raises(InvalidEmbeddingError):
        await store.upsert_embedding(id="a", embedding=[1.0, float("nan")], metadata={})


async def test_query_rejects_empty_embedding(store: ChromaVectorStore) -> None:
    with pytest.raises(InvalidEmbeddingError):
        await store.query_embedding([])


async def test_upsert_coerces_non_primitive_metadata_to_string(store: ChromaVectorStore) -> None:
    await store.upsert_embedding(
        id="a",
        embedding=[1.0],
        metadata={
            "case_id": str(uuid4()),
            "finding_id": str(uuid4()),
            "nested": {"a": 1},  # type: ignore[dict-item]
        },
    )
    assert store.count() == 1


async def test_recorded_at_round_trips(store: ChromaVectorStore) -> None:
    await store.upsert_embedding(
        id="a",
        embedding=[1.0],
        metadata={
            "case_id": str(uuid4()),
            "finding_id": str(uuid4()),
            "recorded_at": "2026-01-01T00:00:00+00:00",
        },
    )
    results = await store.query_embedding([1.0])
    assert results[0].recorded_at is not None
    assert results[0].recorded_at.year == 2026


async def test_missing_recorded_at_defaults_to_none(store: ChromaVectorStore) -> None:
    await store.upsert_embedding(
        id="a", embedding=[1.0], metadata={"case_id": str(uuid4()), "finding_id": str(uuid4())}
    )
    results = await store.query_embedding([1.0])
    assert results[0].recorded_at is None


async def test_persistence_survives_reopening_the_same_directory(tmp_path: object) -> None:
    case_id, finding_id = uuid4(), uuid4()
    first = ChromaVectorStore(persist_dir=str(tmp_path))
    await first.upsert_embedding(
        id="a",
        embedding=[1.0, 0.0],
        metadata={"case_id": str(case_id), "finding_id": str(finding_id)},
    )

    reopened = ChromaVectorStore(persist_dir=str(tmp_path))
    results = await reopened.query_embedding([1.0, 0.0], limit=5)
    assert len(results) == 1
    assert results[0].case_id == case_id
