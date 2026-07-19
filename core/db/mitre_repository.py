"""MITRE reference-table repositories — read-mostly (constitution §7:
these are reference tables, only written by
`scripts/mitre/import_attack_bundle.py`, never by application logic).
Mirrors `core.db.ioc_repository.IOCRepository`'s shape, one small
repository per table rather than one god-repository, per constitution §1.3
("small, focused modules").
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.mitre_group import MitreGroup
from core.db.models.mitre_mitigation import MitreMitigation
from core.db.models.mitre_software import MitreSoftware
from core.db.models.mitre_tactic import MitreTactic
from core.db.models.mitre_technique import MitreTechnique


class MitreTacticRepository(BaseRepository[MitreTactic]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MitreTactic)

    async def find_by_tactic_id(self, tactic_id: str, version: str) -> MitreTactic | None:
        stmt = select(MitreTactic).where(
            MitreTactic.tactic_id == tactic_id, MitreTactic.attack_spec_version == version
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def find_by_version(self, version: str) -> list[MitreTactic]:
        stmt = select(MitreTactic).where(MitreTactic.attack_spec_version == version)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class MitreTechniqueRepository(BaseRepository[MitreTechnique]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MitreTechnique)

    async def find_by_technique_id(self, technique_id: str, version: str) -> MitreTechnique | None:
        stmt = select(MitreTechnique).where(
            MitreTechnique.technique_id == technique_id,
            MitreTechnique.attack_spec_version == version,
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def find_by_version(self, version: str) -> list[MitreTechnique]:
        stmt = select(MitreTechnique).where(MitreTechnique.attack_spec_version == version)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class MitreSoftwareRepository(BaseRepository[MitreSoftware]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MitreSoftware)

    async def find_by_software_id(self, software_id: str, version: str) -> MitreSoftware | None:
        stmt = select(MitreSoftware).where(
            MitreSoftware.software_id == software_id, MitreSoftware.attack_spec_version == version
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()


class MitreGroupRepository(BaseRepository[MitreGroup]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MitreGroup)

    async def find_by_group_id(self, group_id: str, version: str) -> MitreGroup | None:
        stmt = select(MitreGroup).where(
            MitreGroup.group_id == group_id, MitreGroup.attack_spec_version == version
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()


class MitreMitigationRepository(BaseRepository[MitreMitigation]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MitreMitigation)

    async def find_by_mitigation_id(
        self, mitigation_id: str, version: str
    ) -> MitreMitigation | None:
        stmt = select(MitreMitigation).where(
            MitreMitigation.mitigation_id == mitigation_id,
            MitreMitigation.attack_spec_version == version,
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()
