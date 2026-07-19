"""Integration test for core/services/case_service.py — the full blueprint
§9 data flow (ingest -> extract -> generate -> analyze) against a real
SQLite database, the real vendored MITRE bundle, and a real sample evidence
fixture. Mirrors tests/integration/test_finding_mitre_pipeline_integration.py's
"real data, not hand-built fixtures" pattern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.db import Base, Database
from core.db.models.case import CaseStatus
from core.db.models.timeline_event import TimelineEventType
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.services import case_service

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    dataset = load_mitre_dataset(test_settings)
    await import_dataset(db, dataset)
    yield db
    await db.dispose()


async def test_full_pipeline_from_case_creation_to_soc_analysis(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Suspicious SSH activity", analyst_id="local-analyst"
        )
        await session.commit()
        assert case.status == CaseStatus.OPEN

    async with database.session_factory() as session:
        result = await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    assert result.case_id == case.id
    assert result.ioc_count > 0
    assert result.soc_risk_score is not None
    assert result.soc_risk_score > 0.0
    # 12 failed logins from one source IP is a clear brute-force shape.
    assert result.soc_risk_label in {"medium", "high", "critical"}

    async with database.session_factory() as session:
        updated_case = await case_service.get_case(session, case.id)
        assert updated_case is not None
        # First evidence upload transitions OPEN -> INVESTIGATING.
        assert updated_case.status == CaseStatus.INVESTIGATING

        timeline = await case_service.list_timeline_for_case(session, case.id)
        event_types = {event.event_type for event in timeline}
        assert TimelineEventType.CASE_OPENED in event_types
        assert TimelineEventType.EVIDENCE_INGESTED in event_types
        assert TimelineEventType.IOC_EXTRACTED in event_types
        assert TimelineEventType.AGENT_ANALYSIS in event_types
        assert TimelineEventType.CASE_STATUS_CHANGED in event_types


async def test_second_upload_does_not_revert_case_status(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()
    async with database.session_factory() as session:
        case = await case_service.create_case(session, title="Second upload test", analyst_id="a")
        await case_service.update_case_status(session, case.id, CaseStatus.INVESTIGATING)
        await session.commit()

    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
        )
        await session.commit()

    async with database.session_factory() as session:
        updated = await case_service.get_case(session, case.id)
        assert updated is not None
        assert updated.status == CaseStatus.INVESTIGATING
