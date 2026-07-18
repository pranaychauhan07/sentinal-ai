"""`MemoryRepository` — the only place `MemoryRecord` (Pydantic) is translated
to/from `MemoryRecordRow` (SQLAlchemy), per constitution §7. Subclasses
`core.db.BaseRepository` rather than reimplementing CRUD (constitution §14,
"never duplicate functionality") and adds the scope/case-id/expiry query
shapes the memory layer specifically needs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.memory.db_models import MemoryRecordRow
from core.memory.models import MemoryPriority, MemoryQuery, MemoryRecord, MemoryScope


def _row_to_record(row: MemoryRecordRow) -> MemoryRecord:
    return MemoryRecord(
        id=row.id,
        scope=row.scope_enum,
        case_id=row.case_id,
        key=row.key,
        content=row.content,
        tags=tuple(row.tags),
        priority=MemoryPriority(row.priority),
        metadata=dict(row.record_metadata),
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


def _record_to_row(record: MemoryRecord) -> MemoryRecordRow:
    return MemoryRecordRow(
        id=record.id,
        scope=record.scope.value,
        case_id=record.case_id,
        key=record.key,
        content=record.content,
        tags=list(record.tags),
        priority=record.priority.value,
        record_metadata=dict(record.metadata),
        created_at=record.created_at,
        expires_at=record.expires_at,
    )


class MemoryRepository(BaseRepository[MemoryRecordRow]):
    """Async repository for persisted `MemoryRecord`s.

    Constructed the same way every other repository is (session + model),
    matching `tests/unit/test_base_repository.py`'s pattern — no special
    factory function, per constitution §2's dependency-injection rule.
    """

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MemoryRecordRow)

    async def save(self, record: MemoryRecord) -> MemoryRecord:
        """Insert or update a record by id (idempotent upsert via
        merge-by-primary-key, matching SQLAlchemy's `Session.merge`
        semantics rather than a hand-rolled exists-then-insert-or-update
        branch)."""
        row = await self._session.merge(_record_to_row(record))
        await self._session.flush()
        return _row_to_record(row)

    async def find(self, query: MemoryQuery) -> list[MemoryRecord]:
        stmt = select(MemoryRecordRow).order_by(MemoryRecordRow.created_at.desc())
        if query.scope is not None:
            stmt = stmt.where(MemoryRecordRow.scope == query.scope.value)
        if query.case_id is not None:
            stmt = stmt.where(MemoryRecordRow.case_id == query.case_id)
        if query.text is not None:
            stmt = stmt.where(MemoryRecordRow.content.icontains(query.text))
        stmt = stmt.limit(query.limit)
        result = await self._session.execute(stmt)
        records = [_row_to_record(row) for row in result.scalars().all()]
        if query.tags:
            wanted = set(query.tags)
            records = [r for r in records if wanted & set(r.tags)]
        return records

    async def delete_expired(
        self, *, scope: MemoryScope | None = None, now: datetime | None = None
    ) -> int:
        """Purge every row past its `expires_at` — the persistence-layer half
        of `core/memory/lifecycle.py`'s cleanup strategy. Returns the count
        removed, so callers can log/report cleanup activity
        (constitution §8)."""
        cutoff = now or datetime.now(UTC)
        stmt = (
            delete(MemoryRecordRow)
            .where(MemoryRecordRow.expires_at.is_not(None))
            .where(MemoryRecordRow.expires_at <= cutoff)
        )
        if scope is not None:
            stmt = stmt.where(MemoryRecordRow.scope == scope.value)
        result = await self._session.execute(stmt)
        await self._session.flush()
        assert isinstance(result, CursorResult)  # DML statements always return a CursorResult
        return int(result.rowcount or 0)

    async def get_record(self, record_id: UUID) -> MemoryRecord | None:
        row = await self.get_by_id(record_id)
        return _row_to_record(row) if row is not None else None
