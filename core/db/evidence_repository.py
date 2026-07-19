"""`EvidenceRepository` — the sanctioned place raw SQLAlchemy queries against
`Evidence` live (constitution §7, "raw SQLAlchemy queries live behind
repository functions ... never inline inside an agent or a router").
Extends `core.db.base_repository.BaseRepository`'s generic CRUD with the
lookups `core/services/evidence_service.py`'s pipeline actually needs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.evidence import Evidence, EvidenceStatus


class EvidenceRepository(BaseRepository[Evidence]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Evidence)

    async def find_by_case(
        self, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
    ) -> list[Evidence]:
        stmt = (
            select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.id).limit(limit)
        )
        if cursor is not None:
            stmt = stmt.where(Evidence.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_sha256(self, sha256: str) -> Evidence | None:
        """Duplicate-upload detection — the same artifact hash may already
        be on file for this or another case."""
        stmt = select(Evidence).where(Evidence.sha256 == sha256)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def mark_parsed(
        self,
        evidence_id: uuid.UUID,
        *,
        parser_name: str,
        parser_version: str,
        parser_confidence: float,
        parsed_json: str,
    ) -> Evidence | None:
        evidence = await self.get_by_id(evidence_id)
        if evidence is None:
            return None
        evidence.status = EvidenceStatus.PARSED
        evidence.parser_name = parser_name
        evidence.parser_version = parser_version
        evidence.parser_confidence = parser_confidence
        evidence.parsed_json = parsed_json
        evidence.parsed_at = datetime.now(UTC)
        await self._session.flush()
        return evidence

    async def mark_failed(self, evidence_id: uuid.UUID, *, error_message: str) -> Evidence | None:
        evidence = await self.get_by_id(evidence_id)
        if evidence is None:
            return None
        evidence.status = EvidenceStatus.FAILED
        evidence.error_message = error_message
        evidence.parsed_at = datetime.now(UTC)
        await self._session.flush()
        return evidence
