"""`ChromaVectorStore` — the real, persistent `VectorMemory`
(`core/memory/interfaces.py`) production backend (ADR-0027/ADR-0005/
ADR-0010).

Per `docs/dependency-rules.md` rule 6, this is the only module (within
`core/memory`, or anywhere in `core/`) that imports a vector-store client
directly. `chromadb.PersistentClient` runs fully in-process (no server, no
network call) against `Settings.chroma_persist_dir` — there is no async
chromadb client in this project's dependency set, so the methods below are
`async def` only to satisfy the `VectorMemory` Protocol's shape
(constitution §2: "async def for anything touching ... ChromaDB"); the
underlying call is local, in-process work, not blocking I/O over a network.

One collection, `case_findings_embeddings` (blueprint §8's exact name),
configured for cosine similarity (`hnsw:space: cosine`) so
`SimilarResult.score` is always a `[0.0, 1.0]` similarity, not a raw
distance.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

import chromadb

from core.logging import get_logger
from core.memory.exceptions import InvalidEmbeddingError, VectorStoreError
from core.memory.interfaces import SimilarResult, VectorEntry

_logger = get_logger(__name__)

COLLECTION_NAME = "case_findings_embeddings"


def _validate_embedding(embedding: Sequence[float]) -> None:
    if not embedding:
        raise InvalidEmbeddingError("Embedding vector is empty.")
    if any(not math.isfinite(component) for component in embedding):
        raise InvalidEmbeddingError("Embedding vector contains a non-finite value (NaN/inf).")


def _parse_recorded_at(metadata: dict[str, Any]) -> datetime | None:
    """Defensive ISO-8601 parse of a stored ``recorded_at`` metadata value
    (ADR-0028) — mirrors `core.memory.vector_store._parse_recorded_at`
    exactly; kept as a separate copy rather than a shared import since
    neither module is permitted to import the other (both are `VectorMemory`
    implementations at the same layer, not a shared-utility relationship)."""
    raw = metadata.get("recorded_at")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError:
        return None


def _row_to_similar_result(
    *, entry_id: str, metadata: dict[str, Any], distance: float
) -> SimilarResult:
    # Cosine *distance* -> cosine *similarity*, clamped defensively — Chroma
    # guarantees [0, 2] for cosine space, but never trust an external
    # library's numeric range without a clamp at the boundary.
    score = max(0.0, min(1.0, 1.0 - distance))
    return SimilarResult(
        case_id=UUID(str(metadata.get("case_id"))),
        finding_id=UUID(str(metadata.get("finding_id"))),
        score=score,
        excerpt=str(metadata.get("excerpt", "")),
        category=str(metadata.get("category", "finding")),
        recorded_at=_parse_recorded_at(metadata),
    )


class ChromaVectorStore:
    """Persistent, filterable, batch-capable `VectorMemory` backed by a
    local ChromaDB collection."""

    def __init__(self, *, persist_dir: str) -> None:
        try:
            self._client = chromadb.PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
            )
        except Exception as exc:  # noqa: BLE001 - one narrow type for every backend failure
            raise VectorStoreError(
                f"Failed to open ChromaDB collection at {persist_dir!r}: {exc}",
                details={"persist_dir": persist_dir},
            ) from exc

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None:
        await self.upsert_embeddings_batch(
            [VectorEntry(id=id, embedding=embedding, metadata=metadata)]
        )

    async def upsert_embeddings_batch(self, entries: Sequence[VectorEntry]) -> None:
        if not entries:
            return
        for entry in entries:
            _validate_embedding(entry.embedding)
        try:
            # chromadb's stubs declare `embeddings`/`query_embeddings` against a
            # numpy-array-first union that a plain `list[list[float]]` doesn't
            # structurally satisfy under strict invariance — a stub-precision
            # gap (chromadb's own runtime accepts plain lists, verified by this
            # module's own tests), not a real type error in our code; accepted
            # `type: ignore` per constitution's precedent
            # (`core/reporting/pdf_renderer.py`'s `_NumberedCanvas`).
            self._collection.upsert(
                ids=[entry.id for entry in entries],
                embeddings=[entry.embedding for entry in entries],  # type: ignore[arg-type]
                metadatas=[_chroma_safe_metadata(entry.metadata) for entry in entries],
            )
        except Exception as exc:  # noqa: BLE001 - one narrow type for every backend failure
            raise VectorStoreError(f"ChromaDB batch upsert failed: {exc}") from exc

    async def query_embedding(
        self,
        embedding: list[float],
        *,
        limit: int = 5,
        case_id: UUID | None = None,
        metadata_filter: dict[str, str] | None = None,
    ) -> list[SimilarResult]:
        _validate_embedding(embedding)
        where = _build_where(case_id=case_id, metadata_filter=metadata_filter)
        try:
            raw = self._collection.query(
                query_embeddings=[embedding],  # type: ignore[arg-type]
                n_results=limit,
                where=where if where else None,
            )
        except Exception as exc:  # noqa: BLE001 - one narrow type for every backend failure
            raise VectorStoreError(f"ChromaDB query failed: {exc}") from exc

        ids = raw.get("ids") or [[]]
        metadatas = raw.get("metadatas") or [[]]
        distances = raw.get("distances") or [[]]
        results: list[SimilarResult] = []
        for entry_id, metadata, distance in zip(ids[0], metadatas[0], distances[0], strict=True):
            results.append(
                _row_to_similar_result(
                    entry_id=entry_id, metadata=dict(metadata or {}), distance=float(distance)
                )
            )
        return results

    async def delete(self, id: str) -> None:
        try:
            self._collection.delete(ids=[id])
        except Exception as exc:  # noqa: BLE001 - one narrow type for every backend failure
            raise VectorStoreError(f"ChromaDB delete failed for id={id!r}: {exc}") from exc

    async def delete_case(self, case_id: UUID) -> None:
        try:
            self._collection.delete(where={"case_id": str(case_id)})
        except Exception as exc:  # noqa: BLE001 - one narrow type for every backend failure
            raise VectorStoreError(
                f"ChromaDB delete_case failed for case_id={case_id}: {exc}"
            ) from exc

    def count(self) -> int:
        """Total vectors currently stored — a diagnostics/testing helper,
        not part of the `VectorMemory` Protocol."""
        return int(self._collection.count())


def _chroma_safe_metadata(metadata: dict[str, Any]) -> dict[str, str | int | float | bool]:
    """Chroma metadata values must be `str | int | float | bool` — coerce
    anything else (e.g. a nested dict a careless caller passed) to `str`
    rather than letting the client raise a cryptic type error."""
    safe: dict[str, str | int | float | bool] = {}
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)):
            safe[key] = value
        else:
            safe[key] = str(value)
    return safe


def _build_where(*, case_id: UUID | None, metadata_filter: dict[str, str] | None) -> dict[str, Any]:
    clauses: list[dict[str, Any]] = []
    if case_id is not None:
        clauses.append({"case_id": str(case_id)})
    if metadata_filter:
        clauses.extend({key: value} for key, value in metadata_filter.items())
    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}
