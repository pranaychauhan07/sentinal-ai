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
from core.db.models.case import Case, CasePriority, CaseStatus


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

    async def find_open_by_title_and_analyst(self, title: str, analyst_id: str) -> Case | None:
        """ADR-0015 point 10: the exact-match duplicate-case guard's lookup.
        "Open" here means any status short of `RESOLVED`/`CLOSED`/`ARCHIVED`
        — a case still actively being worked."""
        closed_like = {CaseStatus.RESOLVED, CaseStatus.CLOSED, CaseStatus.ARCHIVED}
        stmt = select(Case).where(
            Case.title == title,
            Case.analyst_id == analyst_id,
            Case.status.not_in(closed_like),
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def update_status(self, case_id: uuid.UUID, status: CaseStatus) -> Case | None:
        """Unconditional CRUD write — this repository never enforces
        business rules (constitution §1.4: a repository is CRUD, a service
        coordinates). Transition legality is validated one layer up, by
        `core.services.case_service.update_case_status` calling
        `core.services.case_lifecycle.validate_transition` *before* this
        method is ever called (ADR-0015 point 9) — never inside `core/db`,
        which cannot import `core/services` without an upward, circular
        dependency (`docs/dependency-rules.md`)."""
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        case.status = status
        case.updated_at = datetime.now(UTC)
        if status is CaseStatus.CLOSED:
            case.closed_at = datetime.now(UTC)
        await self._session.flush()
        return case

    async def update_ownership(
        self, case_id: uuid.UUID, *, owner_id: str | None, assignee_id: str | None
    ) -> Case | None:
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        if owner_id is not None:
            case.owner_id = owner_id
        if assignee_id is not None:
            case.assignee_id = assignee_id
        case.updated_at = datetime.now(UTC)
        await self._session.flush()
        return case

    async def update_priority(self, case_id: uuid.UUID, priority: CasePriority) -> Case | None:
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        case.priority = priority
        case.updated_at = datetime.now(UTC)
        await self._session.flush()
        return case

    async def update_risk_score(self, case_id: uuid.UUID, risk_score: float) -> Case | None:
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        case.risk_score = risk_score
        case.updated_at = datetime.now(UTC)
        await self._session.flush()
        return case

    async def update_labels_json(self, case_id: uuid.UUID, labels_json: str) -> Case | None:
        """Store already-serialized JSON — serialization happens in
        `core/services/case_service.py::update_case_labels`, matching the
        `Evidence.parsed_json`/`Finding.finding_data_json` "ORM row is the
        persistence representation" precedent (constitution §7)."""
        case = await self.get_by_id(case_id)
        if case is None:
            return None
        case.labels = labels_json
        case.updated_at = datetime.now(UTC)
        await self._session.flush()
        return case
