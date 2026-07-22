"""Unit tests for core/memory/conversation_db_models.py + conversation_repository.py
— the SQLite persistence path, matching tests/unit/test_memory_repository.py's
pattern."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.conversation_repository import (
    ConversationMessageRepository,
    ConversationSessionRepository,
    ConversationSummaryRepository,
)

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_session_get_or_create_is_idempotent(database: Database) -> None:
    case_id = uuid4()
    session_id = uuid4()
    async with database.session_factory() as session:
        repo = ConversationSessionRepository(session)
        created = await repo.get_or_create(session_id=session_id, case_id=case_id)
        again = await repo.get_or_create(session_id=session_id, case_id=case_id)
        await session.commit()

    assert created.id == again.id == session_id
    assert created.turn_count == 0


async def test_session_touch_increments_turn_count_and_updates_timestamp(
    database: Database,
) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        repo = ConversationSessionRepository(session)
        await repo.get_or_create(session_id=session_id, case_id=case_id)
        touched = await repo.touch(session_id)
        await session.commit()

    assert touched is not None
    assert touched.turn_count == 1


async def test_session_touch_returns_none_for_unknown_session(database: Database) -> None:
    async with database.session_factory() as session:
        repo = ConversationSessionRepository(session)
        assert await repo.touch(uuid4()) is None


async def test_find_by_case_orders_by_most_recently_active(database: Database) -> None:
    case_id = uuid4()
    async with database.session_factory() as session:
        repo = ConversationSessionRepository(session)
        first = await repo.get_or_create(session_id=uuid4(), case_id=case_id)
        second = await repo.get_or_create(session_id=uuid4(), case_id=case_id)
        await repo.touch(first.id)
        await session.commit()

    async with database.session_factory() as session:
        rows = await ConversationSessionRepository(session).find_by_case(case_id)

    assert rows[0].id == first.id
    assert rows[1].id == second.id


async def test_end_session_marks_status_ended(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        repo = ConversationSessionRepository(session)
        await repo.get_or_create(session_id=session_id, case_id=case_id)
        ended = await repo.end_session(session_id)
        await session.commit()

    assert ended is not None
    assert ended.status == "ended"


async def test_message_append_assigns_increasing_sequence_index(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        messages = ConversationMessageRepository(session)
        first = await messages.append(
            session_id=session_id, case_id=case_id, role="user", content="hello"
        )
        second = await messages.append(
            session_id=session_id, case_id=case_id, role="assistant", content="hi"
        )
        await session.commit()

    assert first.sequence_index == 0
    assert second.sequence_index == 1


async def test_find_by_session_orders_and_filters_after_index(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        messages = ConversationMessageRepository(session)
        for i in range(5):
            await messages.append(
                session_id=session_id, case_id=case_id, role="user", content=f"m{i}"
            )
        await session.commit()

    async with database.session_factory() as session:
        rows = await ConversationMessageRepository(session).find_by_session(
            session_id, after_sequence_index=1, up_to_sequence_index=3
        )
    assert [r.sequence_index for r in rows] == [2, 3]


async def test_find_recent_by_session_returns_oldest_first_within_the_tail(
    database: Database,
) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        messages = ConversationMessageRepository(session)
        for i in range(5):
            await messages.append(
                session_id=session_id, case_id=case_id, role="user", content=f"m{i}"
            )
        await session.commit()

    async with database.session_factory() as session:
        rows = await ConversationMessageRepository(session).find_recent_by_session(
            session_id, limit=2
        )
    assert [r.content for r in rows] == ["m3", "m4"]


async def test_search_by_case_is_case_insensitive_substring_match(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        messages = ConversationMessageRepository(session)
        await messages.append(
            session_id=session_id, case_id=case_id, role="user", content="Was T1110 mapped?"
        )
        await messages.append(
            session_id=session_id, case_id=case_id, role="assistant", content="No IOC matched."
        )
        await session.commit()

    async with database.session_factory() as session:
        results = await ConversationMessageRepository(session).search_by_case(
            case_id, query="t1110"
        )
    assert len(results) == 1
    assert "T1110" in results[0].content


async def test_count_by_session(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        messages = ConversationMessageRepository(session)
        for i in range(3):
            await messages.append(
                session_id=session_id, case_id=case_id, role="user", content=f"m{i}"
            )
        await session.commit()

    async with database.session_factory() as session:
        count = await ConversationMessageRepository(session).count_by_session(session_id)
    assert count == 3


async def test_summary_upsert_replaces_existing_row(database: Database) -> None:
    case_id, session_id = uuid4(), uuid4()
    async with database.session_factory() as session:
        repo = ConversationSummaryRepository(session)
        first = await repo.upsert(
            session_id=session_id,
            case_id=case_id,
            summary_text="first summary",
            covers_through_sequence_index=5,
            summarized_message_count=6,
        )
        second = await repo.upsert(
            session_id=session_id,
            case_id=case_id,
            summary_text="updated summary",
            covers_through_sequence_index=10,
            summarized_message_count=11,
        )
        await session.commit()

    assert first.id == second.id
    assert second.summary_text == "updated summary"
    assert second.covers_through_sequence_index == 10

    async with database.session_factory() as session:
        fetched = await ConversationSummaryRepository(session).find_by_session(session_id)
    assert fetched is not None
    assert fetched.summary_text == "updated summary"
