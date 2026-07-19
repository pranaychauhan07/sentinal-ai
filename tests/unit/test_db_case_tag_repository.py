"""Unit tests for core/db/models/case_tag.py + core/db/case_tag_repository.py
— real SQLite, mirroring tests/unit/test_db_case_note_repository.py's
pattern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db import Base, Database
from core.db.case_repository import CaseRepository
from core.db.case_tag_repository import CaseTagRepository
from core.db.models.case import Case, CaseStatus
from core.db.models.case_tag import CaseTag
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
            title="case with tags",
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


async def test_add_and_find_by_case(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        await repo.add(CaseTag(case_id=case.id, tag="phishing", created_at=datetime.now(UTC)))
        await repo.add(CaseTag(case_id=case.id, tag="urgent", created_at=datetime.now(UTC)))
        await session.commit()

        tags = await repo.find_by_case(case.id)
        assert {t.tag for t in tags} == {"phishing", "urgent"}


async def test_duplicate_case_id_and_tag_violates_unique_constraint(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        await repo.add(CaseTag(case_id=case.id, tag="dup", created_at=datetime.now(UTC)))
        await session.commit()

        with pytest.raises(IntegrityError):
            await repo.add(CaseTag(case_id=case.id, tag="dup", created_at=datetime.now(UTC)))


async def test_find_one_returns_none_when_absent(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        assert await repo.find_one(case.id, "missing") is None


async def test_delete_by_case_and_tag(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        await repo.add(CaseTag(case_id=case.id, tag="to-remove", created_at=datetime.now(UTC)))
        await session.commit()

        removed = await repo.delete_by_case_and_tag(case.id, "to-remove")
        assert removed is True
        assert await repo.find_one(case.id, "to-remove") is None


async def test_delete_by_case_and_tag_returns_false_when_absent(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        assert await repo.delete_by_case_and_tag(case.id, "nope") is False


async def test_find_by_case_paginates_with_cursor(database: Database) -> None:
    async with database.session_factory() as session:
        case = await _make_case(session)
        repo = CaseTagRepository(session)
        for tag in ("alpha", "beta", "gamma"):
            await repo.add(CaseTag(case_id=case.id, tag=tag, created_at=datetime.now(UTC)))
        await session.commit()

        first_page = await repo.find_by_case(case.id, limit=1)
        assert len(first_page) == 1
        second_page = await repo.find_by_case(case.id, limit=10, cursor=first_page[0].id)
        assert first_page[0].id not in {t.id for t in second_page}
