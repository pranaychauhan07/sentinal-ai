"""Memory Layer interfaces — abstraction only.

Per the current milestone's explicit scope, no memory *logic* is implemented
here (no ChromaDB client, no persistence) — only the structural contracts
(`typing.Protocol`) that `core/agents/base.py`'s optional memory access point
is typed against, and that a real implementation (Milestone M6,
`docs/roadmap.md`) will satisfy without changing any agent that already
depends on these Protocols.

Mirrors `core.interfaces`'s pattern: pure typing contracts, zero runtime
dependency on ChromaDB or any other concrete backend. Per
`docs/dependency-rules.md` rule 6, only `core/memory/long_term.py` (not yet
implemented) will ever import a vector-store client directly.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


@runtime_checkable
class ShortTermMemory(Protocol):
    """The current investigation's scratchpad. In practice this is just
    `CaseInvestigationState` itself (constitution §4.4: "An agent reads
    short-term memory ... directly") — this Protocol exists so the concept
    has a documented name and a seam for a future dedicated implementation,
    not because agents are expected to depend on it instead of the state
    object directly."""

    def get(self, key: str) -> Any: ...

    def set(self, key: str, value: Any) -> None: ...


@runtime_checkable
class CaseMemory(Protocol):
    """Notes/context scoped to one case but *outside* the graph-execution
    state (e.g. analyst annotations) — distinct from `ShortTermMemory`
    (execution-run scratch data) and from `LongTermMemory` (cross-case). No
    concrete implementation exists yet; `BaseAgent` accepts one optionally
    and works correctly with none (memory is always advisory, never a hard
    dependency — `docs/adr/0006-memory-strategy.md`)."""

    async def get_notes(self, case_id: UUID) -> list[str]: ...

    async def add_note(self, case_id: UUID, note: str) -> None: ...


@runtime_checkable
class LongTermMemory(Protocol):
    """Cross-case retrieval — "has this pattern appeared before?"
    (blueprint §7, Memory Agent). Accessed today through
    `core/services/case_service.py` (write, on investigation completion) and
    `core/services/conversation_service.py` (read, for the AI Analyst
    Chat) — no `core/agents` specialist queries this directly (constitution
    §4.4); there is still no graph-integrated Memory Agent (ADR-0027).

    Extended by ADR-0027: `record` gains a `category` tag; case-scoped and
    cross-case-excluding-this-case retrieval join the original, unscoped
    `find_similar` (kept unchanged for existing callers).
    """

    async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]: ...

    async def find_similar_in_case(
        self, query: str, *, case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]: ...

    async def find_similar_excluding_case(
        self,
        query: str,
        *,
        exclude_case_id: UUID,
        limit: int = 5,
        category: str | None = None,
    ) -> list[SimilarResult]: ...

    async def record(
        self, case_id: UUID, finding_id: UUID, content: str, *, category: str = "finding"
    ) -> None: ...

    async def delete_case(self, case_id: UUID) -> None: ...


class VectorEntry(BaseModel):
    """One typed unit of `upsert_embeddings_batch` input — batch insertion
    needs a structured carrier rather than three parallel positional
    arguments repeated per call (constitution §2, "Pydantic usage")."""

    model_config = ConfigDict(frozen=True)

    id: str
    embedding: list[float]
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class VectorMemory(Protocol):
    """The embedding-store-specific subset of `LongTermMemory` (blueprint
    §8: ChromaDB collection `case_findings_embeddings`). Kept as a separate,
    narrower Protocol so a future non-vector long-term memory backend could
    satisfy `LongTermMemory` without also implementing raw embedding
    operations.

    Extended by ADR-0027 (batch insertion, deletion, case-scoped/metadata-
    filtered query) beyond ADR-0010's original two-method sketch — the
    production bar ("persistent collections, similarity search, metadata
    filtering, case-scoped retrieval, cross-case retrieval, deletion,
    updates, batch insertion") requires it. Every new parameter has a
    backward-compatible default so `core/memory/vector_store.py`'s existing
    two-arg call shape keeps working unchanged.
    """

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None: ...

    async def upsert_embeddings_batch(self, entries: Sequence[VectorEntry]) -> None: ...

    async def query_embedding(
        self,
        embedding: list[float],
        *,
        limit: int = 5,
        case_id: UUID | None = None,
        metadata_filter: dict[str, str] | None = None,
    ) -> list[SimilarResult]: ...

    async def delete(self, id: str) -> None: ...

    async def delete_case(self, case_id: UUID) -> None: ...


class SimilarResult(BaseModel):
    """Typed result shape for a similarity lookup. `finding_id` is the
    record's identifier within its own category (a real Finding id for
    `category="finding"`, the report id for `category="report"`, etc.) —
    kept as the original field name for backward compatibility with every
    existing caller; `category` (added by ADR-0027) is what disambiguates
    it. Blueprint §7's full `SimilarCaseReferences` output model still
    belongs to a future graph-integrated Memory Agent, not this
    interfaces-only module."""

    model_config = ConfigDict(frozen=True)

    case_id: UUID
    finding_id: UUID
    score: float
    excerpt: str
    category: str = "finding"
