"""`LinuxSecurityFindingRepository` — the sanctioned place raw SQLAlchemy
queries against `LinuxSecurityFindingRow` live (constitution §7), extending
`core.db.base_repository.BaseRepository`'s generic CRUD with the lookups
`core/services/linux_security_service.py`'s pipeline needs. Mirrors
`core.db.vulnerability_repository.VulnerabilityRepository`'s shape exactly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.linux_security_finding import (
    LinuxSecurityFindingRow,
    LinuxSecurityFindingStatus,
)


class LinuxSecurityFindingRepository(BaseRepository[LinuxSecurityFindingRow]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, LinuxSecurityFindingRow)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
    ) -> list[LinuxSecurityFindingRow]:
        stmt = (
            select(LinuxSecurityFindingRow)
            .where(LinuxSecurityFindingRow.case_id == case_id)
            .order_by(LinuxSecurityFindingRow.id)
            .limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(LinuxSecurityFindingRow.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_evidence(self, evidence_id: uuid.UUID) -> list[LinuxSecurityFindingRow]:
        stmt = (
            select(LinuxSecurityFindingRow)
            .where(LinuxSecurityFindingRow.evidence_id == evidence_id)
            .order_by(LinuxSecurityFindingRow.id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_subject(
        self, subject: str, *, limit: int = 50
    ) -> list[LinuxSecurityFindingRow]:
        stmt = (
            select(LinuxSecurityFindingRow)
            .where(LinuxSecurityFindingRow.subject == subject)
            .order_by(LinuxSecurityFindingRow.id)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_dismissed(self, finding_id: uuid.UUID) -> LinuxSecurityFindingRow | None:
        row = await self.get_by_id(finding_id)
        if row is None:
            return None
        row.status = LinuxSecurityFindingStatus.DISMISSED
        await self._session.flush()
        return row

    async def mark_false_positive(self, finding_id: uuid.UUID) -> LinuxSecurityFindingRow | None:
        row = await self.get_by_id(finding_id)
        if row is None:
            return None
        row.status = LinuxSecurityFindingStatus.FALSE_POSITIVE
        await self._session.flush()
        return row

    async def increment_occurrence(self, finding_id: uuid.UUID) -> LinuxSecurityFindingRow | None:
        row = await self.get_by_id(finding_id)
        if row is None:
            return None
        row.occurrence_count += 1
        row.last_seen_at = datetime.now(UTC)
        await self._session.flush()
        return row
