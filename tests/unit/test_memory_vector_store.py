"""Unit tests for core/memory/vector_store.py."""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.memory.interfaces import VectorEntry, VectorMemory
from core.memory.vector_store import HashingTextEmbedder, InMemoryVectorStore, NullVectorStore

pytestmark = pytest.mark.unit


async def test_in_memory_vector_store_satisfies_protocol() -> None:
    assert isinstance(InMemoryVectorStore(), VectorMemory)


async def test_null_vector_store_satisfies_protocol() -> None:
    assert isinstance(NullVectorStore(), VectorMemory)


async def test_null_vector_store_is_always_advisory_no_op() -> None:
    store = NullVectorStore()
    await store.upsert_embedding(id="x", embedding=[1.0], metadata={})
    assert await store.query_embedding([1.0]) == []


async def test_in_memory_vector_store_ranks_most_similar_first() -> None:
    store = InMemoryVectorStore()
    case_id, finding_a, finding_b = uuid4(), uuid4(), uuid4()
    await store.upsert_embedding(
        id="a",
        embedding=[1.0, 0.0],
        metadata={"case_id": str(case_id), "finding_id": str(finding_a), "excerpt": "match"},
    )
    await store.upsert_embedding(
        id="b",
        embedding=[0.0, 1.0],
        metadata={"case_id": str(case_id), "finding_id": str(finding_b), "excerpt": "orthogonal"},
    )

    results = await store.query_embedding([1.0, 0.0], limit=2)
    assert results[0].excerpt == "match"
    assert results[0].score > results[1].score


async def test_in_memory_vector_store_respects_limit() -> None:
    store = InMemoryVectorStore()
    for i in range(5):
        await store.upsert_embedding(
            id=str(i),
            embedding=[float(i), 1.0],
            metadata={"case_id": str(uuid4()), "finding_id": str(uuid4())},
        )
    results = await store.query_embedding([1.0, 1.0], limit=2)
    assert len(results) == 2
    assert store.size() == 5


async def test_in_memory_vector_store_batch_upsert() -> None:
    store = InMemoryVectorStore()
    case_id, f1, f2 = uuid4(), uuid4(), uuid4()
    await store.upsert_embeddings_batch(
        [
            VectorEntry(
                id="a",
                embedding=[1.0, 0.0],
                metadata={"case_id": str(case_id), "finding_id": str(f1), "excerpt": "one"},
            ),
            VectorEntry(
                id="b",
                embedding=[0.0, 1.0],
                metadata={"case_id": str(case_id), "finding_id": str(f2), "excerpt": "two"},
            ),
        ]
    )
    assert store.size() == 2


async def test_in_memory_vector_store_case_scoped_query() -> None:
    store = InMemoryVectorStore()
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


async def test_in_memory_vector_store_metadata_filter_query() -> None:
    store = InMemoryVectorStore()
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


async def test_in_memory_vector_store_delete() -> None:
    store = InMemoryVectorStore()
    await store.upsert_embedding(id="a", embedding=[1.0], metadata={})
    await store.delete("a")
    assert store.size() == 0


async def test_in_memory_vector_store_delete_case() -> None:
    store = InMemoryVectorStore()
    case_a, case_b = uuid4(), uuid4()
    await store.upsert_embedding(
        id="a", embedding=[1.0], metadata={"case_id": str(case_a), "finding_id": str(uuid4())}
    )
    await store.upsert_embedding(
        id="b", embedding=[1.0], metadata={"case_id": str(case_b), "finding_id": str(uuid4())}
    )
    await store.delete_case(case_a)
    assert store.size() == 1


async def test_null_vector_store_extended_methods_are_no_ops() -> None:
    store = NullVectorStore()
    await store.upsert_embeddings_batch([VectorEntry(id="a", embedding=[1.0], metadata={})])
    await store.delete("a")
    await store.delete_case(uuid4())
    assert await store.query_embedding([1.0], case_id=uuid4(), metadata_filter={"x": "y"}) == []


async def test_in_memory_vector_store_parses_recorded_at_from_metadata() -> None:
    store = InMemoryVectorStore()
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


async def test_in_memory_vector_store_missing_recorded_at_defaults_to_none() -> None:
    store = InMemoryVectorStore()
    await store.upsert_embedding(
        id="a", embedding=[1.0], metadata={"case_id": str(uuid4()), "finding_id": str(uuid4())}
    )
    results = await store.query_embedding([1.0])
    assert results[0].recorded_at is None


async def test_in_memory_vector_store_malformed_recorded_at_degrades_to_none() -> None:
    store = InMemoryVectorStore()
    await store.upsert_embedding(
        id="a",
        embedding=[1.0],
        metadata={"case_id": str(uuid4()), "finding_id": str(uuid4()), "recorded_at": "not-a-date"},
    )
    results = await store.query_embedding([1.0])
    assert results[0].recorded_at is None


def test_hashing_text_embedder_is_deterministic() -> None:
    embedder = HashingTextEmbedder(dimensions=16)
    assert embedder.embed("brute force login attempt") == embedder.embed(
        "brute force login attempt"
    )


def test_hashing_text_embedder_empty_text_is_zero_vector() -> None:
    embedder = HashingTextEmbedder(dimensions=8)
    assert embedder.embed("") == [0.0] * 8


def test_hashing_text_embedder_similar_text_scores_higher_than_dissimilar() -> None:
    embedder = HashingTextEmbedder(dimensions=64)
    from core.memory.vector_store import _cosine_similarity

    base = embedder.embed("repeated failed ssh login from one ip")
    similar = embedder.embed("repeated failed ssh login attempts from one ip address")
    dissimilar = embedder.embed("quarterly revenue report and marketing budget")

    assert _cosine_similarity(base, similar) > _cosine_similarity(base, dissimilar)
