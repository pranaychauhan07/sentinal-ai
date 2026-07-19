"""Unit tests for core/db/models/finding.py + core/db/finding_repository.py
— real SQLite, mirroring tests/unit/test_db_ioc_repository.py's pattern."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.finding_repository import FindingRepository
from core.db.models.finding import Finding
from core.db.models.finding_mitre_mapping import FindingMitreMapping
from core.db.models.mitre_technique import MitreTechnique
from core.findings.models import FindingPriority, FindingSeverity, FindingStatus


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_finding(
    case_id: uuid.UUID, *, status: FindingStatus = FindingStatus.OPEN, title: str = "Brute Force"
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        case_id=case_id,
        title=title,
        description="test finding",
        severity=FindingSeverity.HIGH,
        confidence=0.75,
        status=status,
        priority=FindingPriority.P2_HIGH,
        risk_score=70.0,
        ioc_count=2,
        finding_data_json="{}",
        created_at=now,
        updated_at=now,
    )


def _make_technique() -> MitreTechnique:
    return MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        description="...",
        tactic_shortnames_json="[]",
        platforms_json="[]",
        attack_spec_version="15.1",
    )


@pytest.mark.unit
async def test_add_and_get_by_id(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.case_id == case_id
        assert fetched.status is FindingStatus.OPEN


@pytest.mark.unit
async def test_find_by_case_scopes_to_case_id(database: Database) -> None:
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        await repo.add(_make_finding(case_a, title="A1"))
        await repo.add(_make_finding(case_a, title="A2"))
        await repo.add(_make_finding(case_b, title="B1"))
        await session.commit()

        results = await repo.find_by_case(case_a)
        assert len(results) == 2
        assert all(f.case_id == case_a for f in results)


@pytest.mark.unit
async def test_find_open_for_case_excludes_closed(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        await repo.add(_make_finding(case_id, status=FindingStatus.OPEN, title="open"))
        await repo.add(_make_finding(case_id, status=FindingStatus.CLOSED, title="closed"))
        await session.commit()

        results = await repo.find_open_for_case(case_id)
        assert len(results) == 1
        assert results[0].title == "open"


@pytest.mark.unit
async def test_mark_closed_updates_status(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        created = await repo.add(_make_finding(case_id))
        await session.commit()

        updated = await repo.mark_closed(created.id)
        await session.commit()

        assert updated is not None
        assert updated.status is FindingStatus.CLOSED


@pytest.mark.unit
async def test_mark_closed_on_missing_id_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        assert await repo.mark_closed(uuid.uuid4()) is None


@pytest.mark.unit
async def test_add_mapping_and_find_by_technique(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        finding_repo = FindingRepository(session)
        finding = await finding_repo.add(_make_finding(case_id))
        technique = _make_technique()
        session.add(technique)
        await session.flush()

        mapping = FindingMitreMapping(
            finding_id=finding.id,
            mitre_technique_id=technique.id,
            confidence=0.8,
            mapping_source="rule_based",
            attack_spec_version="15.1",
        )
        await finding_repo.add_mapping(mapping)
        await session.commit()

        mappings = await finding_repo.mappings_for_finding(finding.id)
        assert len(mappings) == 1
        assert mappings[0].mitre_technique_id == technique.id

        by_technique = await finding_repo.find_by_technique(technique.id)
        assert [f.id for f in by_technique] == [finding.id]
