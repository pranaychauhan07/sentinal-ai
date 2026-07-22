"""Conversation Memory — chat turn history for the AI Analyst Chat
(blueprint §13: "grounded in that case's actual findings via retrieval, not
a generic chatbot").

Kept as its own Protocol distinct from `CaseMemory` per ADR-0010: a
conversation has ordered, role-tagged turns and a token/turn-count budget to
respect, which is a different shape than a bag of tagged notes.

ADR-0029 adds `DbConversationMemory`, a durable backend, alongside
`InMemoryConversationMemory` — exactly the `ChromaVectorStore`-next-to-
`InMemoryVectorStore` shape ADR-0027 already established for `VectorMemory`.
The Protocol gains one additive, defaulted keyword (`session_id`) so a turn
can be correctly scoped to one chat session rather than the whole case's
undifferentiated history; every existing caller that omits it keeps today's
case-wide behavior unchanged on both backends.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from core.memory.conversation_repository import ConversationMessageRepository
from core.memory.models import ConversationRole, ConversationTurn


@runtime_checkable
class ConversationMemory(Protocol):
    """Contract for case-scoped chat history storage."""

    async def get_turns(
        self, case_id: UUID, *, limit: int = 50, session_id: UUID | None = None
    ) -> list[ConversationTurn]: ...

    async def add_turn(
        self,
        case_id: UUID,
        role: ConversationRole,
        content: str,
        *,
        session_id: UUID | None = None,
    ) -> ConversationTurn: ...

    async def clear(self, case_id: UUID, *, session_id: UUID | None = None) -> None: ...


class InMemoryConversationMemory:
    """Process-local `ConversationMemory` — sufficient for a single-analyst,
    single-process deployment (blueprint §3's stated scope), and the
    reference/test/offline implementation once `DbConversationMemory`
    becomes the default (ADR-0029). `session_id` is accepted for Protocol
    compatibility but not used to scope storage here — this backend has
    always been case-wide only; that limitation is exactly why ADR-0029
    added a durable, session-scoped alternative rather than reworking this
    one.
    """

    #: Hard cap per case so one long-running chat session can't grow this
    #: dict without bound (constitution §2, "avoid global state" extended to
    #: unbounded per-instance growth).
    max_turns_per_case: int = 500

    def __init__(self) -> None:
        self._turns: dict[UUID, list[ConversationTurn]] = {}

    async def get_turns(
        self, case_id: UUID, *, limit: int = 50, session_id: UUID | None = None
    ) -> list[ConversationTurn]:
        turns = self._turns.get(case_id, [])
        return turns[-limit:]

    async def add_turn(
        self,
        case_id: UUID,
        role: ConversationRole,
        content: str,
        *,
        session_id: UUID | None = None,
    ) -> ConversationTurn:
        turn = ConversationTurn(role=role, content=content)
        bucket = self._turns.setdefault(case_id, [])
        bucket.append(turn)
        if len(bucket) > self.max_turns_per_case:
            del bucket[: len(bucket) - self.max_turns_per_case]
        return turn

    async def clear(self, case_id: UUID, *, session_id: UUID | None = None) -> None:
        self._turns.pop(case_id, None)


class DbConversationMemory:
    """Durable `ConversationMemory`, backed by
    `core.memory.conversation_repository.ConversationMessageRepository`
    (ADR-0029). Constructed per-request with that request's `AsyncSession`
    — never a process-wide singleton (a DB session is request-scoped by
    construction, constitution §2's dependency-injection rule).

    Unlike `InMemoryConversationMemory`, turns *are* correctly scoped to one
    `session_id` when the caller provides one (the normal case — every real
    caller already has a session id from `SessionManager.get_or_start`).
    When `session_id` is omitted, this backend falls back to the most
    recently active session for the case, so a caller that genuinely has no
    session id yet still gets *a* coherent history rather than an error.
    """

    def __init__(self, message_repository: ConversationMessageRepository) -> None:
        self._messages = message_repository

    async def get_turns(
        self, case_id: UUID, *, limit: int = 50, session_id: UUID | None = None
    ) -> list[ConversationTurn]:
        resolved_session_id = await self._resolve_session_id(case_id, session_id)
        if resolved_session_id is None:
            return []
        rows = await self._messages.find_recent_by_session(resolved_session_id, limit=limit)
        return [
            ConversationTurn(
                id=row.id,
                role=row.role_enum,
                content=row.content,
                created_at=row.created_at,
            )
            for row in rows
        ]

    async def add_turn(
        self,
        case_id: UUID,
        role: ConversationRole,
        content: str,
        *,
        session_id: UUID | None = None,
    ) -> ConversationTurn:
        resolved_session_id = await self._resolve_session_id(case_id, session_id)
        if resolved_session_id is None:
            raise ValueError(
                "DbConversationMemory.add_turn requires a session_id when no prior "
                "session exists for this case."
            )
        row = await self._messages.append(
            session_id=resolved_session_id,
            case_id=case_id,
            role=role.value,
            content=content,
        )
        return ConversationTurn(id=row.id, role=role, content=content, created_at=row.created_at)

    async def clear(self, case_id: UUID, *, session_id: UUID | None = None) -> None:
        # Clearing durable history is a deliberately unsupported operation on
        # this backend: unlike the in-memory dict, these rows are the
        # persisted record replay/export/analytics read from — "clear" would
        # silently destroy audit trail data. Ending a session
        # (`ConversationSessionRepository.end_session`) is the supported
        # equivalent; this backend intentionally leaves message history
        # intact so it stays available for those read paths afterward.
        return None

    async def _resolve_session_id(self, case_id: UUID, session_id: UUID | None) -> UUID | None:
        if session_id is not None:
            return session_id
        recent = await self._messages.find_by_case(case_id, limit=1)
        return recent[0].session_id if recent else None
