"""Unit tests for core/db/models/case_note.py +
core/db/case_note_repository.py — real SQLite, mirroring
tests/unit/test_db_case_repository.py's pattern.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db import Base, Database
from core.db.case_note_repository import CaseNoteRepository
from core.db.case_repository import CaseRepository
from core.db.models.case import Case, CaseStatus
from core.db.models.case_note import CaseNote
from core.parsers.models import Severity

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def _make_case(session: AsyncSession) -> Case:
    now = datetime.now(UTC)
    case = await CaseRepository(session).add(
        Case(
            title="case with notes",
            description="",
            status=CaseStatus.OPEN,
            severity=Severity.INFO,
            analyst_id="local-analyst",
            created_at=now,
            updated_at=now,
        )
    )
    await session.commit()
    return case


def _make_note(
    *, case_id: uuid.UUID, author_id: str = "analyst", body: str = "initial"
) -> CaseNote:
    now = datetime.now(UTC)
    return CaseNote(case_id=case_id, author_id=author_id, body=body, created_at=now, updated_at=now)


async def test_add_and_get_by_id(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseNoteRepository(session)
        created = await repo.add(_make_note(case_id=case.id))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.body == "initial"


async def test_find_by_case_scopes_and_orders(database: Database) -> None:
    async with database.session_factory() as session:
        case_a = await _make_case(session)
        case_b = await _make_case(session)
        repo = CaseNoteRepository(session)
        await repo.add(_make_note(case_id=case_a.id, body="a1"))
        await repo.add(_make_note(case_id=case_a.id, body="a2"))
        await repo.add(_make_note(case_id=case_b.id, body="b1"))
        await session.commit()

        notes = await repo.find_by_case(case_a.id)
        assert [n.body for n in notes] == ["a1", "a2"]


async def test_update_body_bumps_updated_at(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseNoteRepository(session)
        created = await repo.add(_make_note(case_id=case.id))
        await session.commit()
        original_updated_at = created.updated_at

        updated = await repo.update_body(created.id, "edited")
        assert updated is not None
        assert updated.body == "edited"
        assert updated.updated_at >= original_updated_at


async def test_update_body_on_missing_id_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseNoteRepository(session)
        assert await repo.update_body(uuid.uuid4(), "x") is None


async def test_delete_removes_the_note(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseNoteRepository(session)
        created = await repo.add(_make_note(case_id=case.id))
        await session.commit()

        await repo.delete(created.id)
        assert await repo.get_by_id(created.id) is None
