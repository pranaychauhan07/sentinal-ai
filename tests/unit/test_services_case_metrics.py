"""Unit tests for core/services/case_metrics.py — the `CaseMetricsCollector`
(mirroring tests/unit/test_findings_metrics.py's pattern) plus
`compute_case_risk_score` against a real SQLite-backed `FindingRepository`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.finding_repository import FindingRepository
from core.db.models.case import CasePriority, CaseStatus
from core.db.models.finding import Finding
from core.findings.models import FindingPriority, FindingSeverity, FindingStatus
from core.services.case_metrics import CaseMetricsCollector, compute_case_risk_score

pytestmark = pytest.mark.unit


def test_record_case_created_increments_open_and_priority() -> None:
    collector = CaseMetricsCollector()
    collector.record_case_created(CasePriority.HIGH)
    snapshot = collector.snapshot()
    assert snapshot.by_status[CaseStatus.OPEN.value] == 1
    assert snapshot.by_priority[CasePriority.HIGH.value] == 1


def test_record_status_change_moves_the_counter() -> None:
    collector = CaseMetricsCollector()
    collector.record_case_created(CasePriority.MEDIUM)
    collector.record_status_change(CaseStatus.OPEN, CaseStatus.ESCALATED)
    snapshot = collector.snapshot()
    assert snapshot.by_status[CaseStatus.OPEN.value] == 0
    assert snapshot.by_status[CaseStatus.ESCALATED.value] == 1
    assert snapshot.escalations == 1
    assert snapshot.escalation_rate == 1.0


def test_record_resolution_tracks_average_duration() -> None:
    collector = CaseMetricsCollector()
    collector.record_resolution(100.0)
    collector.record_resolution(200.0)
    snapshot = collector.snapshot()
    assert snapshot.resolutions == 2
    assert snapshot.average_resolution_seconds == 150.0


def test_empty_snapshot_has_zeroed_rates() -> None:
    snapshot = CaseMetricsCollector().snapshot()
    assert snapshot.escalation_rate == 0.0
    assert snapshot.average_resolution_seconds == 0.0


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_finding(
    *, case_id: uuid.UUID, risk_score: float, status: FindingStatus = FindingStatus.OPEN
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        case_id=case_id,
        title="t",
        description="",
        severity=FindingSeverity.HIGH,
        confidence=0.8,
        status=status,
        priority=FindingPriority.P2_HIGH,
        risk_score=risk_score,
        ioc_count=1,
        finding_data_json="{}",
        created_at=now,
        updated_at=now,
    )


async def test_compute_case_risk_score_returns_none_with_no_findings(database: Database) -> None:
    async with database.session_factory() as session:
        assert await compute_case_risk_score(session, uuid.uuid4()) is None


async def test_compute_case_risk_score_returns_max_of_open_findings(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = FindingRepository(session)
        await repo.add(_make_finding(case_id=case_id, risk_score=40.0))
        await repo.add(_make_finding(case_id=case_id, risk_score=90.0))
        await repo.add(_make_finding(case_id=case_id, risk_score=99.0, status=FindingStatus.CLOSED))
        await session.commit()

        score = await compute_case_risk_score(session, case_id)
        assert score == 90.0
