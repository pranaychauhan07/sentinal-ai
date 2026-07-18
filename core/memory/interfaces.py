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

from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict


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
    (blueprint §7, Memory Agent). Accessed *only* through the Memory Agent
    per constitution §4.4; no other agent implementation should depend on
    this Protocol directly once a concrete Memory Agent exists."""

    async def find_similar(self, query: str, *, limit: int = 5) -> list[SimilarResult]: ...

    async def record(self, case_id: UUID, finding_id: UUID, content: str) -> None: ...


@runtime_checkable
class VectorMemory(Protocol):
    """The embedding-store-specific subset of `LongTermMemory` (blueprint
    §8: ChromaDB collection `case_findings_embeddings`). Kept as a separate,
    narrower Protocol so a future non-vector long-term memory backend could
    satisfy `LongTermMemory` without also implementing raw embedding
    operations."""

    async def upsert_embedding(
        self, *, id: str, embedding: list[float], metadata: dict[str, Any]
    ) -> None: ...

    async def query_embedding(
        self, embedding: list[float], *, limit: int = 5
    ) -> list[SimilarResult]: ...


class SimilarResult(BaseModel):
    """Minimal typed result shape for a similarity lookup. A placeholder
    kept intentionally small; blueprint §7's full `SimilarCaseReferences`
    output model belongs to the Memory Agent's implementation in
    Milestone M6, not this interfaces-only module."""

    model_config = ConfigDict(frozen=True)

    case_id: UUID
    finding_id: UUID
    score: float
    excerpt: str
