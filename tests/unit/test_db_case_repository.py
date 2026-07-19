"""Unit tests for core/db/models/case.py + core/db/case_repository.py —
real SQLite, mirroring tests/unit/test_db_evidence_repository.py's pattern.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.case_repository import CaseRepository
from core.db.models.case import Case, CaseStatus
from core.parsers.models import Severity

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_case(
    *, title: str = "Suspicious login activity", analyst_id: str = "local-analyst"
) -> Case:
    now = datetime.now(UTC)
    return Case(
        title=title,
        description="",
        status=CaseStatus.OPEN,
        severity=Severity.INFO,
        analyst_id=analyst_id,
        created_at=now,
        updated_at=now,
    )


async def test_add_and_get_by_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.status == CaseStatus.OPEN
        assert fetched.closed_at is None


async def test_find_by_status_scopes_correctly(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        open_case = await repo.add(_make_case(title="open one"))
        closed_case = await repo.add(_make_case(title="closed one"))
        closed_case.status = CaseStatus.CLOSED
        await session.commit()

        open_results = await repo.find_by_status(CaseStatus.OPEN)
        assert {c.id for c in open_results} == {open_case.id}

        closed_results = await repo.find_by_status(CaseStatus.CLOSED)
        assert {c.id for c in closed_results} == {closed_case.id}


async def test_update_status_sets_closed_at_only_on_close(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        investigating = await repo.update_status(created.id, CaseStatus.INVESTIGATING)
        assert investigating is not None
        assert investigating.status == CaseStatus.INVESTIGATING
        assert investigating.closed_at is None

        closed = await repo.update_status(created.id, CaseStatus.CLOSED)
        assert closed is not None
        assert closed.status == CaseStatus.CLOSED
        assert closed.closed_at is not None


async def test_update_status_on_missing_id_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        result = await repo.update_status(uuid.uuid4(), CaseStatus.CLOSED)
        assert result is None
