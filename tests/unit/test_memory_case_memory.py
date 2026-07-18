"""Unit tests for core/memory/case_memory.py."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.case_memory import SQLiteCaseMemory
from core.memory.interfaces import CaseMemory
from core.memory.repository import MemoryRepository

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_sqlite_case_memory_satisfies_protocol(database: Database) -> None:
    async with database.session_factory() as session:
        memory = SQLiteCaseMemory(MemoryRepository(session))
        assert isinstance(memory, CaseMemory)


async def test_add_note_then_get_notes_round_trips(database: Database) -> None:
    case_id = uuid4()
    async with database.session_factory() as session:
        memory = SQLiteCaseMemory(MemoryRepository(session))
        await memory.add_note(case_id, "Sender domain matches a known typosquat.")
        await session.commit()

        notes = await memory.get_notes(case_id)
        assert notes == ["Sender domain matches a known typosquat."]


async def test_get_notes_is_empty_for_unknown_case(database: Database) -> None:
    async with database.session_factory() as session:
        memory = SQLiteCaseMemory(MemoryRepository(session))
        assert await memory.get_notes(uuid4()) == []


async def test_notes_are_scoped_per_case(database: Database) -> None:
    case_a, case_b = uuid4(), uuid4()
    async with database.session_factory() as session:
        memory = SQLiteCaseMemory(MemoryRepository(session))
        await memory.add_note(case_a, "note for A")
        await memory.add_note(case_b, "note for B")
        await session.commit()

        assert await memory.get_notes(case_a) == ["note for A"]
        assert await memory.get_notes(case_b) == ["note for B"]
