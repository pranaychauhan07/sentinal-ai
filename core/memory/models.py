"""Typed contracts every concrete memory store in `core/memory/*.py` reads
and writes — never a bare dict, matching context/03_engineering_constitution.md
§2's Pydantic-usage rule and §4.3's "typed contracts everywhere."

This module has zero dependency on any other `core/memory` module (it is the
leaf the rest of the layer is built from) and zero dependency on `core/db` —
`core/memory/db_models.py` maps these to/from ORM rows, keeping the
persistence mapping in exactly one place per constitution §7.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class MemoryScope(StrEnum):
    """Which lifecycle a `MemoryRecord` belongs to — the single axis every
    lifecycle/cleanup decision (`core/memory/lifecycle.py`) branches on,
    instead of scattered string comparisons."""

    SESSION = "session"
    CASE = "case"
    CONVERSATION = "conversation"
    LONG_TERM = "long_term"


class MemoryPriority(StrEnum):
    """Coarse importance ranking used by `ContextBuilder`'s ranking step and
    by `MemoryLifecycleManager`'s eviction policy (constitution Principle 9:
    ranking is a deterministic function, never left to LLM judgment)."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


_PRIORITY_WEIGHT: dict[MemoryPriority, int] = {
    MemoryPriority.LOW: 0,
    MemoryPriority.NORMAL: 1,
    MemoryPriority.HIGH: 2,
}


class MemoryRecord(BaseModel):
    """One unit of stored memory — a case note, a conversation turn's
    summary, a long-term retrieval candidate. Every concrete store
    (`session_memory.py`, `case_memory.py`, `long_term.py`) reads and writes
    this shape; only `db_models.py`/`repository.py` know how it's persisted.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    scope: MemoryScope
    case_id: UUID | None = None
    key: str
    content: str
    tags: tuple[str, ...] = ()
    priority: MemoryPriority = MemoryPriority.NORMAL
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    @property
    def priority_weight(self) -> int:
        return _PRIORITY_WEIGHT[self.priority]

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or datetime.now(UTC)) >= self.expires_at


class MemoryQuery(BaseModel):
    """Filter/ranking parameters for a memory lookup — every store's
    `query()`-shaped method accepts this instead of a growing list of
    keyword arguments."""

    model_config = ConfigDict(frozen=True)

    scope: MemoryScope | None = None
    case_id: UUID | None = None
    text: str | None = None
    tags: tuple[str, ...] = ()
    limit: int = Field(default=10, gt=0, le=200)


class MemoryQueryResult(BaseModel):
    """One scored match returned from a query — `score` is retrieval
    similarity/relevance in `[0.0, 1.0]`, always deterministic given the same
    backend and input (constitution §5, "Deterministic outputs"), except for
    a genuinely non-deterministic backend, which must document that per the
    same rule."""

    model_config = ConfigDict(frozen=True)

    record: MemoryRecord
    score: float = Field(ge=0.0, le=1.0)


class ConversationRole(StrEnum):
    """Who authored one conversation turn (blueprint §13, AI Analyst Chat)."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class ConversationTurn(BaseModel):
    """One message in a case-scoped chat session. Kept distinct from
    `MemoryRecord` (see ADR-0010) — a conversation has ordered turns with
    roles, not a bag of tagged notes."""

    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    role: ConversationRole
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
