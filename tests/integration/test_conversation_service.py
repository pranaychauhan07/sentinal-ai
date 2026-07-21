"""Integration test for core/services/conversation_service.py — blueprint
§13's AI Analyst Chat, answered from a case that ran through the real
investigation pipeline (mirrors tests/integration/test_case_service_pipeline.py's
"real data, not hand-built fixtures" pattern).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.conversation.exceptions import EmptyQuestionError
from core.db import Base, Database
from core.exceptions import NotFoundError
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.services import case_service, conversation_service

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    dataset = load_mitre_dataset(test_settings)
    await import_dataset(db, dataset)
    yield db
    await db.dispose()


async def test_ask_question_raises_not_found_for_unknown_case(
    database: Database, test_settings: Settings
) -> None:
    async with database.session_factory() as session:
        with pytest.raises(NotFoundError):
            await conversation_service.ask_question(
                session, case_id=uuid.uuid4(), question="anything?", settings=test_settings
            )


async def test_ask_question_rejects_empty_question(
    database: Database, test_settings: Settings
) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Empty question case", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        with pytest.raises(EmptyQuestionError):
            await conversation_service.ask_question(
                session, case_id=case.id, question="   ", settings=test_settings
            )


async def test_ask_question_is_degraded_for_a_case_with_no_evidence_yet(
    database: Database, test_settings: Settings
) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Empty case", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        result = await conversation_service.ask_question(
            session, case_id=case.id, question="What findings exist?", settings=test_settings
        )
    assert result.degraded is True
    assert result.citations == ()


async def test_ask_question_answers_grounded_in_real_pipeline_findings(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Suspicious SSH activity", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    async with database.session_factory() as session:
        result = await conversation_service.ask_question(
            session,
            case_id=case.id,
            question="Were there any brute force login findings?",
            settings=test_settings,
        )

    assert result.degraded is False
    assert len(result.citations) > 0
    assert result.confidence > 0.0

    # A second question in the same session reuses the tracked session id
    # and its conversation history is available for the next turn.
    async with database.session_factory() as session:
        followup = await conversation_service.ask_question(
            session,
            case_id=case.id,
            question="Which technique was mapped?",
            session_id=result.session_id,
            settings=test_settings,
        )
    assert followup.session_id == result.session_id
