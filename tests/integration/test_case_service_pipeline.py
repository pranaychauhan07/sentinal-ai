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
from core.db.models.case import CasePriority, CaseStatus
from core.db.models.timeline_event import TimelineEventType
from core.exceptions import BusinessRuleError
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.services import case_service
from core.services.case_events import CaseEvent, CaseEventPublisher, CaseEventType

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")
_PHISHING_EMAIL = Path("data/sample_evidence/phishing_sample_01.eml")
_LEGITIMATE_EMAIL = Path("data/sample_evidence/legitimate_sample_01.eml")


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


async def test_phishing_email_upload_routes_to_phishing_agent_not_soc(
    database: Database, test_settings: Settings
) -> None:
    """M2/M3 demo criterion: a `.eml` upload's evidence-type-based capability
    routing (`case_service._required_capability_for`) fans out to
    `PhishingAgent`, not `SocAnalystAgent` — and the IOCs already extracted
    from the email (sender/URL) are attributed and scored into the verdict."""
    content = _PHISHING_EMAIL.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Suspicious email report", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        result = await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="phishing_sample_01.eml",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    assert result.case_id == case.id
    assert result.ioc_count > 0
    assert result.soc_risk_score is None
    assert result.soc_risk_label is None
    assert result.phishing_risk_score is not None
    assert result.phishing_risk_label in {"medium", "high", "critical"}

    async with database.session_factory() as session:
        timeline = await case_service.list_timeline_for_case(session, case.id)
        event_types = {event.event_type for event in timeline}
        assert TimelineEventType.EVIDENCE_INGESTED in event_types
        assert TimelineEventType.IOC_EXTRACTED in event_types
        assert TimelineEventType.AGENT_ANALYSIS in event_types


async def test_legitimate_email_upload_scores_low_risk(
    database: Database, test_settings: Settings
) -> None:
    content = _LEGITIMATE_EMAIL.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Routine notification email", analyst_id="local-analyst"
        )
        await session.commit()

        result = await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="legitimate_sample_01.eml",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    assert result.phishing_risk_score is not None
    assert result.phishing_risk_label in {"info", "low"}


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


async def test_investigate_new_evidence_recomputes_case_risk_score(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()
    async with database.session_factory() as session:
        case = await case_service.create_case(session, title="Risk rollup test", analyst_id="a")
        await session.commit()

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
        assert updated.risk_score is not None
        assert updated.risk_score > 0.0


async def test_full_lifecycle_escalation_path_records_timeline_and_events(
    database: Database,
) -> None:
    published: list[CaseEvent] = []
    publisher = CaseEventPublisher()
    publisher.subscribe(published.append)

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Escalation path", analyst_id="a", event_publisher=publisher
        )
        await session.commit()

        for target in (
            CaseStatus.INVESTIGATING,
            CaseStatus.ESCALATED,
            CaseStatus.CONTAINED,
            CaseStatus.RESOLVED,
            CaseStatus.CLOSED,
        ):
            await case_service.update_case_status(
                session, case.id, target, event_publisher=publisher
            )
            await session.commit()

    async with database.session_factory() as session:
        final_case = await case_service.get_case(session, case.id)
        assert final_case is not None
        assert final_case.status == CaseStatus.CLOSED

        timeline = await case_service.list_timeline_for_case(session, case.id)
        status_changes = [
            e for e in timeline if e.event_type == TimelineEventType.CASE_STATUS_CHANGED
        ]
        assert len(status_changes) == 5

    published_types = [e.event_type for e in published]
    assert CaseEventType.CASE_CREATED in published_types
    assert CaseEventType.CASE_ESCALATED in published_types
    assert CaseEventType.CASE_RESOLVED in published_types
    assert CaseEventType.CASE_CLOSED in published_types


async def test_illegal_transition_raises_and_does_not_mutate_status(database: Database) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(session, title="Illegal jump", analyst_id="a")
        await session.commit()

        with pytest.raises(BusinessRuleError):
            await case_service.update_case_status(session, case.id, CaseStatus.ARCHIVED)

    async with database.session_factory() as session:
        unchanged = await case_service.get_case(session, case.id)
        assert unchanged is not None
        assert unchanged.status == CaseStatus.OPEN


async def test_create_case_rejects_exact_duplicate_for_same_analyst(database: Database) -> None:
    async with database.session_factory() as session:
        await case_service.create_case(session, title="Dup title", analyst_id="analyst-x")
        await session.commit()

        with pytest.raises(BusinessRuleError):
            await case_service.create_case(session, title="Dup title", analyst_id="analyst-x")


async def test_create_case_allows_same_title_for_different_analyst(database: Database) -> None:
    async with database.session_factory() as session:
        await case_service.create_case(session, title="Shared title", analyst_id="analyst-x")
        await session.commit()

        other = await case_service.create_case(
            session, title="Shared title", analyst_id="analyst-y"
        )
        assert other.title == "Shared title"


async def test_note_lifecycle_records_paired_timeline_events(database: Database) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(session, title="Note case", analyst_id="a")
        await session.commit()

        note = await case_service.add_case_note(session, case.id, author_id="a", body="first")
        await session.commit()
        await case_service.update_case_note(session, note.id, body="edited")
        await session.commit()
        await case_service.delete_case_note(session, note.id)
        await session.commit()

    async with database.session_factory() as session:
        timeline = await case_service.list_timeline_for_case(session, case.id)
        note_events = [e for e in timeline if e.event_type == TimelineEventType.MANUAL_NOTE]
        assert len(note_events) == 3

        remaining_notes = await case_service.list_case_notes(session, case.id)
        assert remaining_notes == []


async def test_tag_and_priority_and_assignment_updates(database: Database) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(session, title="Tag case", analyst_id="a")
        await session.commit()

        await case_service.add_case_tag(session, case.id, "phishing")
        await case_service.add_case_tag(session, case.id, "phishing")  # idempotent
        await case_service.update_case_priority(session, case.id, CasePriority.CRITICAL)
        await case_service.update_case_assignment(
            session, case.id, owner_id="owner-1", assignee_id="assignee-1"
        )
        await session.commit()

    async with database.session_factory() as session:
        tags = await case_service.list_case_tags(session, case.id)
        assert [t.tag for t in tags] == ["phishing"]

        updated_case = await case_service.get_case(session, case.id)
        assert updated_case is not None
        assert updated_case.priority == CasePriority.CRITICAL
        assert updated_case.owner_id == "owner-1"
        assert updated_case.assignee_id == "assignee-1"

        timeline = await case_service.list_timeline_for_case(session, case.id)
        assert any(e.event_type == TimelineEventType.CASE_ASSIGNED for e in timeline)
