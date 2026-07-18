"""`SQLiteCaseMemory` — the first concrete `CaseMemory` (`core/memory/interfaces.py`)
implementation.

Satisfies `BaseAgent`'s existing `case_memory: CaseMemory | None` constructor
parameter (`core/agents/base.py`) for real, for the first time — no change
to `BaseAgent` required, matching ADR-0010's stated goal. Notes are analyst
annotations scoped to a case but outside the graph-execution
`CaseInvestigationState` (constitution §4.4's distinction), persisted via
`MemoryRepository` so they outlive any single graph run or process restart.
"""

from __future__ import annotations

from uuid import UUID

from core.logging import get_logger
from core.memory.models import MemoryQuery, MemoryRecord, MemoryScope
from core.memory.repository import MemoryRepository

_logger = get_logger(__name__)


class SQLiteCaseMemory:
    """`CaseMemory` backed by `MemoryRepository` (SQLite via the shared
    `core/db` engine, or any other dialect `Database` is configured for —
    this class never branches on dialect, per `core/db/session.py`)."""

    def __init__(self, repository: MemoryRepository) -> None:
        self._repository = repository

    async def get_notes(self, case_id: UUID) -> list[str]:
        records = await self._repository.find(
            MemoryQuery(scope=MemoryScope.CASE, case_id=case_id, limit=200)
        )
        return [record.content for record in records]

    async def add_note(self, case_id: UUID, note: str) -> None:
        record = MemoryRecord(
            scope=MemoryScope.CASE,
            case_id=case_id,
            key=f"note:{case_id}",
            content=note,
        )
        await self._repository.save(record)
        _logger.info("case_note_added", case_id=str(case_id))
