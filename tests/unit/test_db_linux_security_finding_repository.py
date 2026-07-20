"""Unit tests for core/db/models/linux_security_finding.py + core/db/
linux_security_finding_repository.py — real SQLite, mirroring
tests/unit/test_db_vulnerability_repository.py's pattern."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.linux_security_finding_repository import LinuxSecurityFindingRepository
from core.db.models.linux_security_finding import (
    LinuxSecurityFindingRow,
    LinuxSecurityFindingStatus,
)
from core.linux_security.models import LinuxSecurityFindingCategory, LinuxSecuritySeverity


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_finding(case_id: uuid.UUID, *, subject: str = "203.0.113.44") -> LinuxSecurityFindingRow:
    now = datetime.now(UTC)
    return LinuxSecurityFindingRow(
        case_id=case_id,
        category=LinuxSecurityFindingCategory.BRUTE_FORCE,
        subject=subject,
        subject_type="ip",
        title="SSH brute force",
        description="desc",
        severity=LinuxSecuritySeverity.HIGH,
        composite_score=80.0,
        occurrence_count=6,
        extractor_name="linux_security_pipeline",
        extractor_version="1.0.0",
        status=LinuxSecurityFindingStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )


@pytest.mark.unit
async def test_add_and_get_by_id(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.status == LinuxSecurityFindingStatus.ACTIVE
        assert fetched.case_id == case_id
        assert fetched.category == LinuxSecurityFindingCategory.BRUTE_FORCE


@pytest.mark.unit
async def test_find_by_case_scopes_to_case_id(database: Database) -> None:
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        await repo.add(_make_finding(case_a, subject="1.1.1.1"))
        await repo.add(_make_finding(case_a, subject="2.2.2.2"))
        await repo.add(_make_finding(case_b, subject="3.3.3.3"))
        await session.commit()

        results = await repo.find_by_case(case_a)
        assert len(results) == 2
        assert all(r.case_id == case_a for r in results)


@pytest.mark.unit
async def test_find_by_evidence(database: Database) -> None:
    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        row = _make_finding(case_id)
        row.evidence_id = evidence_id
        await repo.add(row)
        await repo.add(_make_finding(case_id))
        await session.commit()

        results = await repo.find_by_evidence(evidence_id)
        assert len(results) == 1
        assert results[0].evidence_id == evidence_id


@pytest.mark.unit
async def test_find_by_subject(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        await repo.add(_make_finding(case_id, subject="203.0.113.44"))
        await repo.add(_make_finding(case_id, subject="198.51.100.9"))
        await session.commit()

        results = await repo.find_by_subject("203.0.113.44")
        assert len(results) == 1
        assert results[0].subject == "203.0.113.44"


@pytest.mark.unit
async def test_mark_dismissed(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        updated = await repo.mark_dismissed(created.id)
        assert updated is not None
        assert updated.status == LinuxSecurityFindingStatus.DISMISSED


@pytest.mark.unit
async def test_mark_false_positive(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        updated = await repo.mark_false_positive(created.id)
        assert updated is not None
        assert updated.status == LinuxSecurityFindingStatus.FALSE_POSITIVE


@pytest.mark.unit
async def test_mark_dismissed_on_missing_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        assert await repo.mark_dismissed(uuid.uuid4()) is None


@pytest.mark.unit
async def test_increment_occurrence(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = LinuxSecurityFindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        updated = await repo.increment_occurrence(created.id)
        assert updated is not None
        assert updated.occurrence_count == 7
