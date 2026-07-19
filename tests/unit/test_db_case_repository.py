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
from core.db.models.case import Case, CasePriority, CaseStatus
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


async def test_update_status_is_unconditional_crud(database: Database) -> None:
    """`CaseRepository.update_status` never validates transitions itself
    (ADR-0015 point 9) — an "illegal" jump like OPEN -> ARCHIVED succeeds at
    this layer; only `core.services.case_service.update_case_status` (which
    calls `core.services.case_lifecycle.validate_transition` first) rejects
    it."""
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        archived = await repo.update_status(created.id, CaseStatus.ARCHIVED)
        assert archived is not None
        assert archived.status == CaseStatus.ARCHIVED


async def test_find_open_by_title_and_analyst_excludes_closed_like_statuses(
    database: Database,
) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        open_case = await repo.add(_make_case(title="dup", analyst_id="a1"))
        await session.commit()

        found = await repo.find_open_by_title_and_analyst("dup", "a1")
        assert found is not None
        assert found.id == open_case.id

        await repo.update_status(open_case.id, CaseStatus.CLOSED)
        await session.commit()

        assert await repo.find_open_by_title_and_analyst("dup", "a1") is None


async def test_find_open_by_title_and_analyst_scopes_by_analyst(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        await repo.add(_make_case(title="shared title", analyst_id="a1"))
        await session.commit()

        assert await repo.find_open_by_title_and_analyst("shared title", "a2") is None


async def test_update_ownership_updates_only_provided_fields(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        with_owner = await repo.update_ownership(created.id, owner_id="owner-1", assignee_id=None)
        assert with_owner is not None
        assert with_owner.owner_id == "owner-1"
        assert with_owner.assignee_id is None

        with_assignee = await repo.update_ownership(
            created.id, owner_id=None, assignee_id="assignee-1"
        )
        assert with_assignee is not None
        assert with_assignee.owner_id == "owner-1"
        assert with_assignee.assignee_id == "assignee-1"


async def test_update_priority(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        updated = await repo.update_priority(created.id, CasePriority.CRITICAL)
        assert updated is not None
        assert updated.priority == CasePriority.CRITICAL


async def test_update_risk_score(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        updated = await repo.update_risk_score(created.id, 87.5)
        assert updated is not None
        assert updated.risk_score == 87.5


async def test_update_labels_json(database: Database) -> None:
    async with database.session_factory() as session:
        repo = CaseRepository(session)
        created = await repo.add(_make_case())
        await session.commit()

        updated = await repo.update_labels_json(created.id, '{"env": "prod"}')
        assert updated is not None
        assert updated.labels == '{"env": "prod"}'
