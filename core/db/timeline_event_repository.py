"""`TimelineEventRepository` — the sanctioned place raw SQLAlchemy queries
against `TimelineEvent` live (constitution §7)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.timeline_event import TimelineEvent


class TimelineEventRepository(BaseRepository[TimelineEvent]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, TimelineEvent)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
    ) -> list[TimelineEvent]:
        stmt = (
            select(TimelineEvent)
            .where(TimelineEvent.case_id == case_id)
            .order_by(TimelineEvent.timestamp, TimelineEvent.id)
            .limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(TimelineEvent.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
