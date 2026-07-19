"""`CaseTagRepository` — the sanctioned place raw SQLAlchemy queries against
`CaseTag` live (constitution §7), mirroring `core.db.case_repository.
CaseRepository`'s shape.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.case_tag import CaseTag


class CaseTagRepository(BaseRepository[CaseTag]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, CaseTag)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
    ) -> list[CaseTag]:
        stmt = (
            select(CaseTag)
            .where(CaseTag.case_id == case_id)
            .order_by(CaseTag.tag, CaseTag.id)
            .limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(CaseTag.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_one(self, case_id: uuid.UUID, tag: str) -> CaseTag | None:
        stmt = select(CaseTag).where(CaseTag.case_id == case_id, CaseTag.tag == tag)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def delete_by_case_and_tag(self, case_id: uuid.UUID, tag: str) -> bool:
        existing = await self.find_one(case_id, tag)
        if existing is None:
            return False
        await self.delete(existing.id)
        return True
