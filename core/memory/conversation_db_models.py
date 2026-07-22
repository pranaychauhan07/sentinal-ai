"""SQLAlchemy persistence models for case-scoped chat history
(`core/memory/conversation_memory.py`'s `DbConversationMemory` backend).

Mirrors `core/memory/db_models.py`'s established pattern exactly (a
`core/memory`-owned ORM row importing `core.db.session.Entity` directly, not
a new module inside `core/db`) — see `docs/adr/0029-conversation-persistence-
compression-export.md` Decision 1. Unlike `MemoryRecordRow` (written before
the `Case` table existed), `case_id` here is a real foreign key: `cases`
already exists, so there is no reason to leave it a plain UUID column
(constitution §7, "Future scalability" — additive, not a redesign of
`MemoryRecordRow`, which stays exactly as it is).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.memory.models import ConversationRole


class ConversationSessionRow(Entity):
    """One durable chat session record. `id` is always assigned explicitly
    by the caller (matching `core.conversation.models.ConversationSession.
    session_id`, which `SessionManager` generates first) rather than relying
    on `Entity`'s `default=uuid.uuid4` — the persisted row and the
    in-process `SessionManager` entry must share one id."""

    __tablename__ = "conversation_sessions"
    __table_args__ = (Index("ix_conversation_sessions_case_id", "case_id"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    turn_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    last_active_at: Mapped[datetime] = mapped_column(nullable=False)


class ConversationMessageRow(Entity):
    """One persisted chat turn. `case_id` is denormalized alongside
    `session_id` (both indexed) so case-wide reads (search, analytics that
    span every session in a case) never need a join through
    `ConversationSessionRow` — the same "denormalized column for indexed
    list queries" precedent `Finding.case_id` already set even though
    `Finding.primary_evidence_id` could theoretically be traversed instead.
    """

    __tablename__ = "conversation_messages"
    __table_args__ = (
        Index("ix_conversation_messages_session_id", "session_id", "sequence_index"),
        Index("ix_conversation_messages_case_id", "case_id"),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversation_sessions.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    sequence_index: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: Serialized `list[core.conversation.models.SourceReference]` — `"[]"`
    #: for a `user` turn, which never carries citations.
    citations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Serialized `list[str]` of `core.conversation.models.EvidenceCategory`
    #: values selected for this turn (empty for a `user` turn).
    selected_categories_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    prompt_injection_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)

    @property
    def role_enum(self) -> ConversationRole:
        return ConversationRole(self.role)


class ConversationSummaryRow(Entity):
    """One session's rolling compression summary — upserted (one row per
    session, replaced as the conversation grows further), the same "1 row
    per parent, replaced not appended" cardinality
    `core.db.models.report.Report`/`IncidentResponsePlanRow` already use for
    their per-case rows."""

    __tablename__ = "conversation_summaries"
    __table_args__ = (Index("ix_conversation_summaries_session_id", "session_id", unique=True),)

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversation_sessions.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    summary_text: Mapped[str] = mapped_column(Text, nullable=False)
    #: The highest `ConversationMessageRow.sequence_index` this summary
    #: already accounts for — turns at or below this index are represented
    #: only by the summary, never re-sent verbatim to the prompt.
    covers_through_sequence_index: Mapped[int] = mapped_column(Integer, nullable=False)
    summarized_message_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
