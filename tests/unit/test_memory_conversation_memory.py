"""Unit tests for core/memory/conversation_memory.py."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.conversation_memory import (
    ConversationMemory,
    DbConversationMemory,
    InMemoryConversationMemory,
)
from core.memory.conversation_repository import ConversationMessageRepository
from core.memory.models import ConversationRole

pytestmark = pytest.mark.unit


async def test_in_memory_conversation_memory_satisfies_protocol() -> None:
    assert isinstance(InMemoryConversationMemory(), ConversationMemory)


async def test_add_turn_then_get_turns_round_trips() -> None:
    memory = InMemoryConversationMemory()
    case_id = uuid4()
    await memory.add_turn(case_id, ConversationRole.USER, "Why was this High severity?")
    await memory.add_turn(case_id, ConversationRole.ASSISTANT, "Because of repeated failed logins.")

    turns = await memory.get_turns(case_id)
    assert [t.role for t in turns] == [ConversationRole.USER, ConversationRole.ASSISTANT]


async def test_get_turns_respects_limit() -> None:
    memory = InMemoryConversationMemory()
    case_id = uuid4()
    for i in range(5):
        await memory.add_turn(case_id, ConversationRole.USER, f"message {i}")

    turns = await memory.get_turns(case_id, limit=2)
    assert len(turns) == 2
    assert turns[-1].content == "message 4"


async def test_max_turns_per_case_bounds_growth() -> None:
    memory = InMemoryConversationMemory()
    memory.max_turns_per_case = 3
    case_id = uuid4()
    for i in range(10):
        await memory.add_turn(case_id, ConversationRole.USER, f"m{i}")

    turns = await memory.get_turns(case_id, limit=100)
    assert len(turns) == 3
    assert turns[-1].content == "m9"


async def test_clear_removes_all_turns_for_a_case() -> None:
    memory = InMemoryConversationMemory()
    case_id = uuid4()
    await memory.add_turn(case_id, ConversationRole.USER, "hi")
    await memory.clear(case_id)
    assert await memory.get_turns(case_id) == []


async def test_conversations_are_isolated_per_case() -> None:
    memory = InMemoryConversationMemory()
    case_a, case_b = uuid4(), uuid4()
    await memory.add_turn(case_a, ConversationRole.USER, "a")
    await memory.add_turn(case_b, ConversationRole.USER, "b")

    assert [t.content for t in await memory.get_turns(case_a)] == ["a"]
    assert [t.content for t in await memory.get_turns(case_b)] == ["b"]


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_db_conversation_memory_satisfies_protocol(database: Database) -> None:
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        assert isinstance(memory, ConversationMemory)


async def test_db_conversation_memory_add_then_get_turns_round_trips(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        await memory.add_turn(
            case_id, ConversationRole.USER, "Why High severity?", session_id=session_id
        )
        await memory.add_turn(
            case_id,
            ConversationRole.ASSISTANT,
            "Repeated failed logins.",
            session_id=session_id,
        )
        await session.commit()

    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        turns = await memory.get_turns(case_id, session_id=session_id)
    assert [t.role for t in turns] == [ConversationRole.USER, ConversationRole.ASSISTANT]
    assert turns[1].content == "Repeated failed logins."


async def test_db_conversation_memory_add_turn_requires_a_resolvable_session(
    database: Database,
) -> None:
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        with pytest.raises(ValueError):
            await memory.add_turn(uuid4(), ConversationRole.USER, "no session yet")


async def test_db_conversation_memory_get_turns_falls_back_to_most_recent_session(
    database: Database,
) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        await memory.add_turn(case_id, ConversationRole.USER, "hi", session_id=session_id)
        await session.commit()

    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        turns = await memory.get_turns(case_id)
    assert [t.content for t in turns] == ["hi"]


async def test_db_conversation_memory_get_turns_returns_empty_for_unknown_case(
    database: Database,
) -> None:
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        assert await memory.get_turns(uuid4()) == []


async def test_db_conversation_memory_clear_is_a_documented_no_op(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        await memory.add_turn(case_id, ConversationRole.USER, "hi", session_id=session_id)
        await session.commit()

    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        await memory.clear(case_id, session_id=session_id)

    async with database.session_factory() as session:
        memory = DbConversationMemory(ConversationMessageRepository(session))
        turns = await memory.get_turns(case_id, session_id=session_id)
    assert len(turns) == 1
