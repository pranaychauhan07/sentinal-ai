"""Unit tests for core/db/models/report.py + core/db/report_repository.py —
real SQLite, mirroring tests/unit/test_db_incident_response_plan_repository.py's
pattern.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.report_repository import ReportRepository
from core.reporting.models import GeneratedReport, ReportType, ReportValidationResult


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _report_data(
    case_id: uuid.UUID, *, report_type: ReportType = ReportType.TECHNICAL_INVESTIGATION
) -> dict[str, object]:
    report = GeneratedReport(
        case_id=str(case_id),
        report_type=report_type,
        title="Technical Investigation Report",
        validation=ReportValidationResult(is_complete=True),
        confidence=0.8,
    )
    return report.model_dump(mode="json")


@pytest.mark.unit
async def test_upsert_and_find_by_case(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = ReportRepository(session)
        row = await repo.upsert_for_case(case_id, _report_data(case_id))
        await session.commit()

        assert row.case_id == case_id
        assert row.report_type == ReportType.TECHNICAL_INVESTIGATION
        assert row.overall_confidence == 0.8

        fetched = await repo.find_by_case(case_id)
        assert fetched is not None
        assert fetched.id == row.id


@pytest.mark.unit
async def test_upsert_replaces_existing_row_not_appends(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = ReportRepository(session)
        first = await repo.upsert_for_case(case_id, _report_data(case_id))
        await session.commit()

        second_data = _report_data(case_id, report_type=ReportType.EXECUTIVE)
        second = await repo.upsert_for_case(case_id, second_data)
        await session.commit()

        assert second.id == first.id
        assert second.report_type == ReportType.EXECUTIVE

        all_rows = await repo.list(limit=10)
        assert len([r for r in all_rows if r.case_id == case_id]) == 1


@pytest.mark.unit
async def test_find_by_case_returns_none_when_no_report_exists(database: Database) -> None:
    async with database.session_factory() as session:
        repo = ReportRepository(session)
        assert await repo.find_by_case(uuid.uuid4()) is None
