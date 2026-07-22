"""Repositories for `core/memory/conversation_db_models.py` — the only place
raw SQLAlchemy queries against `ConversationSessionRow`/
`ConversationMessageRow`/`ConversationSummaryRow` live (constitution §7),
mirroring `core.memory.repository.MemoryRepository`'s shape: subclass
`core.db.BaseRepository` rather than reimplementing CRUD (constitution §14.9).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.memory.conversation_db_models import (
    ConversationMessageRow,
    ConversationSessionRow,
    ConversationSummaryRow,
)


class ConversationSessionRepository(BaseRepository[ConversationSessionRow]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ConversationSessionRow)

    async def get_or_create(
        self, *, session_id: uuid.UUID, case_id: uuid.UUID
    ) -> ConversationSessionRow:
        existing = await self.get_by_id(session_id)
        if existing is not None:
            return existing
        now = datetime.now(UTC)
        row = ConversationSessionRow(
            id=session_id,
            case_id=case_id,
            status="active",
            turn_count=0,
            created_at=now,
            last_active_at=now,
        )
        return await self.add(row)

    async def touch(self, session_id: uuid.UUID) -> ConversationSessionRow | None:
        row = await self.get_by_id(session_id)
        if row is None:
            return None
        row.turn_count += 1
        row.last_active_at = datetime.now(UTC)
        await self._session.flush()
        return row

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 50
    ) -> list[ConversationSessionRow]:
        stmt = (
            select(ConversationSessionRow)
            .where(ConversationSessionRow.case_id == case_id)
            .order_by(ConversationSessionRow.last_active_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def end_session(self, session_id: uuid.UUID) -> ConversationSessionRow | None:
        row = await self.get_by_id(session_id)
        if row is None:
            return None
        row.status = "ended"
        await self._session.flush()
        return row


class ConversationMessageRepository(BaseRepository[ConversationMessageRow]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ConversationMessageRow)

    async def next_sequence_index(self, session_id: uuid.UUID) -> int:
        stmt = select(func.max(ConversationMessageRow.sequence_index)).where(
            ConversationMessageRow.session_id == session_id
        )
        result = await self._session.execute(stmt)
        current_max = result.scalar_one_or_none()
        return 0 if current_max is None else current_max + 1

    async def append(
        self,
        *,
        session_id: uuid.UUID,
        case_id: uuid.UUID,
        role: str,
        content: str,
        citations_json: str = "[]",
        confidence: float | None = None,
        degraded: bool = False,
        selected_categories_json: str = "[]",
        prompt_injection_flagged: bool = False,
    ) -> ConversationMessageRow:
        sequence_index = await self.next_sequence_index(session_id)
        row = ConversationMessageRow(
            session_id=session_id,
            case_id=case_id,
            sequence_index=sequence_index,
            role=role,
            content=content,
            citations_json=citations_json,
            confidence=confidence,
            degraded=degraded,
            selected_categories_json=selected_categories_json,
            prompt_injection_flagged=prompt_injection_flagged,
            created_at=datetime.now(UTC),
        )
        return await self.add(row)

    async def find_by_session(
        self,
        session_id: uuid.UUID,
        *,
        limit: int = 500,
        after_sequence_index: int = -1,
        up_to_sequence_index: int | None = None,
    ) -> list[ConversationMessageRow]:
        stmt = (
            select(ConversationMessageRow)
            .where(ConversationMessageRow.session_id == session_id)
            .where(ConversationMessageRow.sequence_index > after_sequence_index)
        )
        if up_to_sequence_index is not None:
            stmt = stmt.where(ConversationMessageRow.sequence_index <= up_to_sequence_index)
        stmt = stmt.order_by(ConversationMessageRow.sequence_index.asc()).limit(limit)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_recent_by_session(
        self, session_id: uuid.UUID, *, limit: int = 20
    ) -> list[ConversationMessageRow]:
        stmt = (
            select(ConversationMessageRow)
            .where(ConversationMessageRow.session_id == session_id)
            .order_by(ConversationMessageRow.sequence_index.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(reversed(result.scalars().all()))

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 200
    ) -> list[ConversationMessageRow]:
        stmt = (
            select(ConversationMessageRow)
            .where(ConversationMessageRow.case_id == case_id)
            .order_by(ConversationMessageRow.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def search_by_case(
        self, case_id: uuid.UUID, *, query: str, limit: int = 50
    ) -> list[ConversationMessageRow]:
        """Case-insensitive substring search over this case's persisted chat
        content — the "Conversation Search" requirement. Deterministic and
        cheap (constitution §5): no embedding/semantic search here, matching
        `core.conversation.retrieval.RetrievalLayer`'s own documented
        keyword-only scope boundary for the same reason."""
        stmt = (
            select(ConversationMessageRow)
            .where(ConversationMessageRow.case_id == case_id)
            .where(ConversationMessageRow.content.icontains(query))
            .order_by(ConversationMessageRow.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_session(self, session_id: uuid.UUID) -> int:
        stmt = select(func.count(ConversationMessageRow.id)).where(
            ConversationMessageRow.session_id == session_id
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


class ConversationSummaryRepository(BaseRepository[ConversationSummaryRow]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ConversationSummaryRow)

    async def find_by_session(self, session_id: uuid.UUID) -> ConversationSummaryRow | None:
        stmt = select(ConversationSummaryRow).where(ConversationSummaryRow.session_id == session_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert(
        self,
        *,
        session_id: uuid.UUID,
        case_id: uuid.UUID,
        summary_text: str,
        covers_through_sequence_index: int,
        summarized_message_count: int,
    ) -> ConversationSummaryRow:
        existing = await self.find_by_session(session_id)
        now = datetime.now(UTC)
        if existing is not None:
            existing.summary_text = summary_text
            existing.covers_through_sequence_index = covers_through_sequence_index
            existing.summarized_message_count = summarized_message_count
            existing.updated_at = now
            await self._session.flush()
            return existing
        row = ConversationSummaryRow(
            session_id=session_id,
            case_id=case_id,
            summary_text=summary_text,
            covers_through_sequence_index=covers_through_sequence_index,
            summarized_message_count=summarized_message_count,
            created_at=now,
            updated_at=now,
        )
        return await self.add(row)
