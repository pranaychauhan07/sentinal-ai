"""Unit tests for core/db/models/ioc.py + core/db/ioc_repository.py — real
SQLite, mirroring tests/unit/test_db_evidence_repository.py's pattern."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.ioc_repository import IOCRepository
from core.db.models.ioc import IOC, IOCStatus
from core.threat_intel.models import IOCType, ThreatCategory, ThreatSeverity


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_ioc(
    case_id: uuid.UUID, *, value: str = "1.2.3.4", ioc_type: IOCType = IOCType.IPV4
) -> IOC:
    now = datetime.now(UTC)
    return IOC(
        case_id=case_id,
        ioc_type=ioc_type,
        value=value,
        raw_value=value,
        source="test",
        confidence=0.8,
        severity=ThreatSeverity.MEDIUM,
        classification=ThreatCategory.SUSPICIOUS,
        composite_score=55.0,
        rule_match_count=0,
        occurrence_count=1,
        extractor_name="ioc_extraction_engine",
        extractor_version="1.0.0",
        status=IOCStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )


@pytest.mark.unit
async def test_add_and_get_by_id(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        created = await repo.add(_make_ioc(case_id))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.status == IOCStatus.ACTIVE
        assert fetched.case_id == case_id


@pytest.mark.unit
async def test_find_by_case_scopes_to_case_id(database: Database) -> None:
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        await repo.add(_make_ioc(case_a, value="1.1.1.1"))
        await repo.add(_make_ioc(case_a, value="2.2.2.2"))
        await repo.add(_make_ioc(case_b, value="3.3.3.3"))
        await session.commit()

        results = await repo.find_by_case(case_a)
        assert len(results) == 2
        assert all(ioc.case_id == case_a for ioc in results)


@pytest.mark.unit
async def test_find_by_evidence_scopes_to_evidence_id(database: Database) -> None:
    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        ioc = _make_ioc(case_id)
        ioc.evidence_id = evidence_id
        await repo.add(ioc)
        await repo.add(_make_ioc(case_id, value="9.9.9.9"))
        await session.commit()

        results = await repo.find_by_evidence(evidence_id)
        assert len(results) == 1
        assert results[0].evidence_id == evidence_id


@pytest.mark.unit
async def test_find_by_value_and_type_detects_duplicate(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        created = await repo.add(_make_ioc(case_id, value="1.2.3.4"))
        await session.commit()

        found = await repo.find_by_value_and_type("1.2.3.4", IOCType.IPV4)
        assert found is not None
        assert found.id == created.id

        not_found = await repo.find_by_value_and_type("1.2.3.4", IOCType.DOMAIN)
        assert not_found is None


@pytest.mark.unit
async def test_mark_dismissed_updates_status(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        created = await repo.add(_make_ioc(case_id))
        await session.commit()

        updated = await repo.mark_dismissed(created.id)
        await session.commit()

        assert updated is not None
        assert updated.status == IOCStatus.DISMISSED


@pytest.mark.unit
async def test_mark_false_positive_updates_status(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        created = await repo.add(_make_ioc(case_id))
        await session.commit()

        updated = await repo.mark_false_positive(created.id)
        await session.commit()

        assert updated is not None
        assert updated.status == IOCStatus.FALSE_POSITIVE


@pytest.mark.unit
async def test_increment_occurrence_bumps_count_and_last_seen(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        created = await repo.add(_make_ioc(case_id))
        await session.commit()
        original_last_seen = created.last_seen_at

        updated = await repo.increment_occurrence(created.id)
        await session.commit()

        assert updated is not None
        assert updated.occurrence_count == 2
        assert updated.last_seen_at >= original_last_seen


@pytest.mark.unit
async def test_mark_dismissed_on_missing_id_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = IOCRepository(session)
        assert await repo.mark_dismissed(uuid.uuid4()) is None
