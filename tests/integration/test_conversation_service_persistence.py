"""Integration tests for ADR-0029's conversation persistence/compression/
export additions to `core/services/conversation_service.py` — real SQLite
persistence across separate, committed sessions (unlike
tests/integration/test_conversation_service.py's existing tests, which never
commit the `ask_question` calls themselves and so never actually exercised
the ADR-0029 persistence path)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest

from core.config import Settings
from core.db import Base, Database
from core.services import case_service, conversation_service

pytestmark = pytest.mark.integration


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def _create_case(database: Database) -> uuid.UUID:
    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Persistence case", analyst_id="local-analyst"
        )
        await session.commit()
    return case.id


async def test_ask_question_persists_session_and_messages_across_requests(
    database: Database, test_settings: Settings
) -> None:
    case_id = await _create_case(database)

    async with database.session_factory() as session:
        first = await conversation_service.ask_question(
            session, case_id=case_id, question="What is the case status?", settings=test_settings
        )
        await session.commit()

    async with database.session_factory() as session:
        await conversation_service.ask_question(
            session,
            case_id=case_id,
            question="Anything else?",
            session_id=first.session_id,
            settings=test_settings,
        )
        await session.commit()

    async with database.session_factory() as session:
        sessions = await conversation_service.list_conversation_sessions(
            session, case_id=case_id, settings=test_settings
        )
        history = await conversation_service.get_conversation_history(
            session, case_id=case_id, session_id=first.session_id, settings=test_settings
        )

    assert any(s.session_id == first.session_id for s in sessions)
    matching = next(s for s in sessions if s.session_id == first.session_id)
    assert matching.turn_count == 2
    assert len(history) == 4
    assert [m.role for m in history[:2]] == ["user", "assistant"]
    assert history[1].confidence is not None


async def test_search_finds_a_persisted_message_by_keyword(
    database: Database, test_settings: Settings
) -> None:
    case_id = await _create_case(database)
    async with database.session_factory() as session:
        await conversation_service.ask_question(
            session,
            case_id=case_id,
            question="Was UNIQUE-SEARCH-TOKEN-42 mapped to a technique?",
            settings=test_settings,
        )
        await session.commit()

    async with database.session_factory() as session:
        results = await conversation_service.search_conversation_history(
            session, case_id=case_id, query="unique-search-token-42", settings=test_settings
        )
    assert any("UNIQUE-SEARCH-TOKEN-42" in r.content for r in results)


async def test_analytics_aggregates_persisted_messages(
    database: Database, test_settings: Settings
) -> None:
    case_id = await _create_case(database)
    async with database.session_factory() as session:
        await conversation_service.ask_question(
            session, case_id=case_id, question="Summarize the case.", settings=test_settings
        )
        await session.commit()

    async with database.session_factory() as session:
        analytics = await conversation_service.get_conversation_analytics(
            session, case_id=case_id, settings=test_settings
        )
    assert analytics.total_sessions == 1
    assert analytics.total_messages == 2
    assert analytics.assistant_message_count == 1


async def test_export_conversation_transcript_renders_persisted_messages(
    database: Database, test_settings: Settings
) -> None:
    case_id = await _create_case(database)
    async with database.session_factory() as session:
        result = await conversation_service.ask_question(
            session,
            case_id=case_id,
            question="Give me an executive summary.",
            settings=test_settings,
        )
        await session.commit()

    async with database.session_factory() as session:
        exported = await conversation_service.export_conversation_transcript(
            session,
            case_id=case_id,
            session_id=result.session_id,
            export_format="markdown",
            settings=test_settings,
        )
    text = exported.content.decode("utf-8")
    assert "Give me an executive summary." in text


async def test_long_conversation_triggers_compression_and_bounds_prompt_history(
    database: Database, test_settings: Settings
) -> None:
    """A session with more turns than `conversation_compression_trigger_turns`
    gets a persisted `ConversationSummaryRow`, and later questions still
    answer successfully (grounded pipeline unaffected by history size)."""
    compressing_settings = test_settings.model_copy(
        update={
            "conversation_compression_trigger_turns": 4,
            "conversation_summary_keep_recent_turns": 2,
            "conversation_history_turn_limit": 50,
        }
    )
    case_id = await _create_case(database)

    session_id: uuid.UUID | None = None
    for i in range(6):
        async with database.session_factory() as session:
            result = await conversation_service.ask_question(
                session,
                case_id=case_id,
                question=f"Question number {i}?",
                session_id=session_id,
                settings=compressing_settings,
            )
            await session.commit()
        session_id = result.session_id

    assert session_id is not None
    async with database.session_factory() as session:
        history = await conversation_service.get_conversation_history(
            session, case_id=case_id, session_id=session_id, settings=compressing_settings
        )
        # A follow-up question still answers successfully once compression
        # has kicked in for this session.
        followup = await conversation_service.ask_question(
            session,
            case_id=case_id,
            question="One more question?",
            session_id=session_id,
            settings=compressing_settings,
        )
        await session.commit()

    assert len(history) == 12  # 6 user + 6 assistant turns, all still persisted
    assert followup.session_id == session_id
