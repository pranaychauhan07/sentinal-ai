"""Conversation Memory — chat turn history for the future AI Analyst Chat
(blueprint §13: "grounded in that case's actual findings via retrieval, not
a generic chatbot").

Kept as its own Protocol distinct from `CaseMemory` per ADR-0010: a
conversation has ordered, role-tagged turns and a token/turn-count budget to
respect, which is a different shape than a bag of tagged notes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from core.memory.models import ConversationRole, ConversationTurn


@runtime_checkable
class ConversationMemory(Protocol):
    """Contract for case-scoped chat history storage."""

    async def get_turns(self, case_id: UUID, *, limit: int = 50) -> list[ConversationTurn]: ...

    async def add_turn(
        self, case_id: UUID, role: ConversationRole, content: str
    ) -> ConversationTurn: ...

    async def clear(self, case_id: UUID) -> None: ...


class InMemoryConversationMemory:
    """Process-local `ConversationMemory` — sufficient for a single-analyst,
    single-process deployment (blueprint §3's stated scope); a persisted
    implementation is a drop-in swap behind the same Protocol later,
    following the same pattern `core/memory/vector_store.py` documents for
    ChromaDB.
    """

    #: Hard cap per case so one long-running chat session can't grow this
    #: dict without bound (constitution §2, "avoid global state" extended to
    #: unbounded per-instance growth).
    max_turns_per_case: int = 500

    def __init__(self) -> None:
        self._turns: dict[UUID, list[ConversationTurn]] = {}

    async def get_turns(self, case_id: UUID, *, limit: int = 50) -> list[ConversationTurn]:
        turns = self._turns.get(case_id, [])
        return turns[-limit:]

    async def add_turn(
        self, case_id: UUID, role: ConversationRole, content: str
    ) -> ConversationTurn:
        turn = ConversationTurn(role=role, content=content)
        bucket = self._turns.setdefault(case_id, [])
        bucket.append(turn)
        if len(bucket) > self.max_turns_per_case:
            del bucket[: len(bucket) - self.max_turns_per_case]
        return turn

    async def clear(self, case_id: UUID) -> None:
        self._turns.pop(case_id, None)
