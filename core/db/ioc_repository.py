"""`IOCRepository` — the sanctioned place raw SQLAlchemy queries against
`IOC` live (constitution §7), extending `core.db.base_repository.
BaseRepository`'s generic CRUD with the lookups
`core/services/threat_intel_service.py`'s pipeline needs. Mirrors
`core.db.evidence_repository.EvidenceRepository`'s shape exactly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.ioc import IOC, IOCStatus
from core.threat_intel.models import IOCType


class IOCRepository(BaseRepository[IOC]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, IOC)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
    ) -> list[IOC]:
        stmt = select(IOC).where(IOC.case_id == case_id).order_by(IOC.id).limit(limit)
        if cursor is not None:
            stmt = stmt.where(IOC.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_evidence(self, evidence_id: uuid.UUID) -> list[IOC]:
        stmt = select(IOC).where(IOC.evidence_id == evidence_id).order_by(IOC.id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_value_and_type(self, value: str, ioc_type: IOCType) -> IOC | None:
        """Dedup lookup — has this exact normalized IOC already been
        persisted (in this or another case)? A future cross-case
        correlation feature (explicitly out of scope for this session's
        pipeline, docs/adr/0012) would build on this primitive."""
        stmt = select(IOC).where(IOC.value == value, IOC.ioc_type == ioc_type)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def find_by_type(self, ioc_type: IOCType, *, limit: int = 50) -> list[IOC]:
        stmt = select(IOC).where(IOC.ioc_type == ioc_type).order_by(IOC.id).limit(limit)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_dismissed(self, ioc_id: uuid.UUID) -> IOC | None:
        ioc = await self.get_by_id(ioc_id)
        if ioc is None:
            return None
        ioc.status = IOCStatus.DISMISSED
        await self._session.flush()
        return ioc

    async def mark_false_positive(self, ioc_id: uuid.UUID) -> IOC | None:
        ioc = await self.get_by_id(ioc_id)
        if ioc is None:
            return None
        ioc.status = IOCStatus.FALSE_POSITIVE
        await self._session.flush()
        return ioc

    async def increment_occurrence(self, ioc_id: uuid.UUID) -> IOC | None:
        """Bump `occurrence_count` and `last_seen_at` when the same IOC is
        observed again in a later extraction run against the same case."""
        ioc = await self.get_by_id(ioc_id)
        if ioc is None:
            return None
        ioc.occurrence_count += 1
        ioc.last_seen_at = datetime.now(UTC)
        await self._session.flush()
        return ioc
