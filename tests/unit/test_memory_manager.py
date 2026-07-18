"""Unit tests for core/memory/manager.py."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.case_memory import SQLiteCaseMemory
from core.memory.conversation_memory import InMemoryConversationMemory
from core.memory.long_term import LongTermMemoryManager
from core.memory.manager import MemoryManager
from core.memory.models import ConversationRole, MemoryRecord, MemoryScope
from core.memory.repository import MemoryRepository
from core.memory.vector_store import HashingTextEmbedder, InMemoryVectorStore

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_manager_with_no_optional_backends_degrades_gracefully() -> None:
    manager = MemoryManager()
    case_id = uuid4()

    assert await manager.get_case_notes(case_id) == []
    await manager.add_case_note(case_id, "should be a no-op")  # must not raise
    assert await manager.get_conversation(case_id) == []
    assert await manager.find_similar_findings("query") == []
    await manager.record_finding(case_id, uuid4(), "content")  # must not raise
    assert await manager.cleanup() is None


async def test_manager_wires_case_notes_through_to_sqlite(database: Database) -> None:
    async with database.session_factory() as session:
        manager = MemoryManager(case_memory=SQLiteCaseMemory(MemoryRepository(session)))
        case_id = uuid4()

        await manager.add_case_note(case_id, "escalated to on-call")
        await session.commit()

        notes = await manager.get_case_notes(case_id)
        assert notes == ["escalated to on-call"]
        assert manager.metrics.snapshot().writes == 1


async def test_manager_wires_conversation_memory() -> None:
    manager = MemoryManager(conversation_memory=InMemoryConversationMemory())
    case_id = uuid4()

    await manager.add_conversation_turn(case_id, ConversationRole.USER, "explain finding #4")
    turns = await manager.get_conversation(case_id)
    assert len(turns) == 1
    assert turns[0].content == "explain finding #4"


async def test_manager_wires_long_term_memory() -> None:
    long_term = LongTermMemoryManager(
        vector_store=InMemoryVectorStore(), embedder=HashingTextEmbedder()
    )
    manager = MemoryManager(long_term_memory=long_term)
    case_id, finding_id = uuid4(), uuid4()

    await manager.record_finding(case_id, finding_id, "repeated failed logins")
    results = await manager.find_similar_findings("failed logins")
    assert len(results) == 1
    assert results[0].finding_id == finding_id


def test_render_context_serializes_assembled_records() -> None:
    manager = MemoryManager()
    record = MemoryRecord(scope=MemoryScope.CASE, key="k", content="brute force")
    assert manager.render_context([record]) == "[case] brute force"
