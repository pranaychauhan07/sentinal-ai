"""`CaseNoteRepository` — the sanctioned place raw SQLAlchemy queries against
`CaseNote` live (constitution §7), mirroring `core.db.case_repository.
CaseRepository`'s shape.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.case_note import CaseNote


class CaseNoteRepository(BaseRepository[CaseNote]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, CaseNote)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
    ) -> list[CaseNote]:
        stmt = (
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at, CaseNote.id)
            .limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(CaseNote.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_body(self, note_id: uuid.UUID, body: str) -> CaseNote | None:
        note = await self.get_by_id(note_id)
        if note is None:
            return None
        note.body = body
        note.updated_at = datetime.now(UTC)
        await self._session.flush()
        return note
