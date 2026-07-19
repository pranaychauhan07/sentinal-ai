"""`FindingRepository` — the sanctioned place raw SQLAlchemy queries against
`Finding`/`FindingMitreMapping` live (constitution §7), mirroring
`core.db.ioc_repository.IOCRepository`'s shape exactly.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.finding import Finding
from core.db.models.finding_mitre_mapping import FindingMitreMapping
from core.findings.models import FindingStatus


class FindingRepository(BaseRepository[Finding]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Finding)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.case_id == case_id).order_by(Finding.id).limit(limit)
        if cursor is not None:
            stmt = stmt.where(Finding.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_open_for_case(self, case_id: uuid.UUID) -> list[Finding]:
        """The dedup engine's candidate pool — only `OPEN` Findings are
        eligible merge targets (a `CLOSED`/`MERGED` Finding is not a normal
        merge target; `core.findings.dedup.merge_findings` reopens a closed
        Finding explicitly if it is chosen as one)."""
        stmt = select(Finding).where(
            Finding.case_id == case_id, Finding.status == FindingStatus.OPEN
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_status(self, case_id: uuid.UUID, status: FindingStatus) -> list[Finding]:
        stmt = select(Finding).where(Finding.case_id == case_id, Finding.status == status)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_technique(self, mitre_technique_row_id: uuid.UUID) -> list[Finding]:
        stmt = (
            select(Finding)
            .join(FindingMitreMapping, FindingMitreMapping.finding_id == Finding.id)
            .where(FindingMitreMapping.mitre_technique_id == mitre_technique_row_id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_closed(self, finding_id: uuid.UUID) -> Finding | None:
        finding = await self.get_by_id(finding_id)
        if finding is None:
            return None
        finding.status = FindingStatus.CLOSED
        await self._session.flush()
        return finding

    async def add_mapping(self, mapping: FindingMitreMapping) -> FindingMitreMapping:
        self._session.add(mapping)
        await self._session.flush()
        return mapping

    async def mappings_for_finding(self, finding_id: uuid.UUID) -> list[FindingMitreMapping]:
        stmt = select(FindingMitreMapping).where(FindingMitreMapping.finding_id == finding_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
