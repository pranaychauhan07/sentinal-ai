"""`ReportRepository` — the sanctioned place raw SQLAlchemy queries against
`Report` live (constitution §7). Only the generic CRUD `BaseRepository`
already provides is needed this session — no report-generation logic exists
yet (Milestone M5), so no extra finder methods are added ahead of a real
caller (constitution §8, no placeholder logic).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.report import Report


class ReportRepository(BaseRepository[Report]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Report)
