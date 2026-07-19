"""Unit tests for core/db/models/timeline_event.py + core/db/
timeline_event_repository.py — real SQLite."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.models.timeline_event import TimelineEvent, TimelineEventType
from core.db.timeline_event_repository import TimelineEventRepository

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _event(case_id: uuid.UUID, *, offset_seconds: int, narrative: str) -> TimelineEvent:
    return TimelineEvent(
        case_id=case_id,
        timestamp=datetime.now(UTC) + timedelta(seconds=offset_seconds),
        event_type=TimelineEventType.EVIDENCE_INGESTED,
        narrative=narrative,
    )


async def test_find_by_case_orders_chronologically(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = TimelineEventRepository(session)
        await repo.add(_event(case_id, offset_seconds=10, narrative="second"))
        await repo.add(_event(case_id, offset_seconds=0, narrative="first"))
        await session.commit()

        results = await repo.find_by_case(case_id)
        assert [e.narrative for e in results] == ["first", "second"]


async def test_find_by_case_scopes_to_case_id(database: Database) -> None:
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    async with database.session_factory() as session:
        repo = TimelineEventRepository(session)
        await repo.add(_event(case_a, offset_seconds=0, narrative="a"))
        await repo.add(_event(case_b, offset_seconds=0, narrative="b"))
        await session.commit()

        results = await repo.find_by_case(case_a)
        assert len(results) == 1
        assert results[0].narrative == "a"
