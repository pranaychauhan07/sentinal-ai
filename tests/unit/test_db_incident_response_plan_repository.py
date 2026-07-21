"""Unit tests for core/db/models/incident_response_plan.py + core/db/
incident_response_plan_repository.py — real SQLite, mirroring
tests/unit/test_db_linux_security_finding_repository.py's pattern."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.incident_response_plan_repository import IncidentResponsePlanRepository
from core.incident_response.models import IncidentResponsePlan, IncidentSeverity


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _plan_data(case_id: uuid.UUID, *, recommendation_count: int = 0) -> dict[str, object]:
    plan = IncidentResponsePlan(
        case_id=str(case_id),
        incident_severity=IncidentSeverity.HIGH,
        overall_risk_score=70.0,
        overall_confidence=0.9,
        recommendations=(),
    )
    return plan.model_dump(mode="json")


@pytest.mark.unit
async def test_upsert_and_find_by_case(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IncidentResponsePlanRepository(session)
        row = await repo.upsert_for_case(case_id, _plan_data(case_id))
        await session.commit()

        assert row.case_id == case_id
        assert row.incident_severity == IncidentSeverity.HIGH
        assert row.overall_risk_score == 70.0

        fetched = await repo.find_by_case(case_id)
        assert fetched is not None
        assert fetched.id == row.id


@pytest.mark.unit
async def test_upsert_replaces_existing_row_not_appends(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = IncidentResponsePlanRepository(session)
        first = await repo.upsert_for_case(case_id, _plan_data(case_id))
        await session.commit()

        updated_plan = IncidentResponsePlan(
            case_id=str(case_id),
            incident_severity=IncidentSeverity.CRITICAL,
            overall_risk_score=99.0,
            overall_confidence=1.0,
            recommendations=(),
        )
        second = await repo.upsert_for_case(case_id, updated_plan.model_dump(mode="json"))
        await session.commit()

        assert second.id == first.id
        assert second.incident_severity == IncidentSeverity.CRITICAL
        assert second.overall_risk_score == 99.0


@pytest.mark.unit
async def test_find_by_case_returns_none_when_no_plan_exists(database: Database) -> None:
    async with database.session_factory() as session:
        repo = IncidentResponsePlanRepository(session)
        assert await repo.find_by_case(uuid.uuid4()) is None
