"""`SessionManager` — the task's named "Session Manager".

Tracks active chat sessions (id, case_id, timestamps, turn count) as a
process-local registry — metadata only, never turn *content* (that stays
`core.memory.conversation_memory.ConversationMemory`'s job, kept there per
docs/adr/0025 Decision 1). Mirrors `core.memory.conversation_memory.
InMemoryConversationMemory`'s identical "sufficient for a single-analyst,
single-process deployment" scope (ADR-0010) — a persisted implementation is
a drop-in swap behind the same shape later, not a redesign.
"""

from __future__ import annotations

from uuid import UUID

from core.conversation.models import ConversationSession

#: Hard cap so one long-running process can't accumulate unbounded session
#: metadata (constitution §2, "avoid global state" extended to unbounded
#: per-instance growth) — mirrors `InMemoryConversationMemory.
#: max_turns_per_case`'s identical bound.
MAX_TRACKED_SESSIONS = 1_000


class SessionManager:
    """An explicit, injectable registry (constitution §2) — construct one
    per process/test, never a module-level singleton mutated implicitly."""

    def __init__(self) -> None:
        self._sessions: dict[UUID, ConversationSession] = {}

    def start_session(self, case_id: str) -> ConversationSession:
        if len(self._sessions) >= MAX_TRACKED_SESSIONS:
            oldest_id = min(self._sessions, key=lambda sid: self._sessions[sid].last_active_at)
            del self._sessions[oldest_id]
        session = ConversationSession(case_id=case_id)
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: UUID) -> ConversationSession | None:
        return self._sessions.get(session_id)

    def get_or_start(self, *, session_id: UUID | None, case_id: str) -> ConversationSession:
        if session_id is not None:
            existing = self.get_session(session_id)
            if existing is not None:
                return existing
        return self.start_session(case_id)

    def record_turn(self, session_id: UUID) -> ConversationSession | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        touched = session.touched()
        self._sessions[session_id] = touched
        return touched

    def end_session(self, session_id: UUID) -> None:
        self._sessions.pop(session_id, None)
