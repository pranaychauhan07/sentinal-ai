"""`CaseRepository` — the sanctioned place raw SQLAlchemy queries against
`Case` live (constitution §7), mirroring `core.db.evidence_repository.
EvidenceRepository`'s shape.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.case import Case, CaseStatus


class CaseRepository(BaseRepository[Case]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Case)

    async def find_by_status(
        self, status: CaseStatus, *, limit: int = 50, cursor: uuid.UUID | None = None
    ) -> list[Case]:
        stmt = select(Case).where(Case.status == status).order_by(Case.id).limit(limit)
        if cursor is not None:
            stmt = stmt.where(Case.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(self, case_id: uuid.UUID, status: CaseStatus) -> Case | None:
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        case.status = status
        case.updated_at = datetime.now(UTC)
        if status is CaseStatus.CLOSED:
            case.closed_at = datetime.now(UTC)
        await self._session.flush()
        return case
