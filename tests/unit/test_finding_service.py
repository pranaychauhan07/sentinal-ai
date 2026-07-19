"""Unit tests for core/services/finding_service.py — the full Finding
Generation Pipeline and its generate_findings_for_case() orchestrator,
mirroring tests/unit/test_threat_intel_service.py's pattern exactly."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from tests.unit._finding_test_helpers import make_scored_ioc

from core.config import Settings
from core.db import Base, Database
from core.db.finding_repository import FindingRepository
from core.db.ioc_repository import IOCRepository
from core.db.mitre_repository import MitreTechniqueRepository
from core.db.models.ioc import IOC, IOCStatus
from core.db.models.mitre_technique import MitreTechnique
from core.findings.events import FindingEvent, FindingEventPublisher
from core.findings.models import FindingStatus
from core.services.finding_service import (
    FindingGenerationPipeline,
    generate_findings_for_case,
    get_finding,
    list_findings_for_case,
)


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def _seed_technique(session, technique_id: str, name: str, version: str = "15.1") -> None:
    repo = MitreTechniqueRepository(session)
    await repo.add(
        MitreTechnique(
            technique_id=technique_id,
            name=name,
            description="seeded for test",
            tactic_shortnames_json="[]",
            platforms_json="[]",
            attack_spec_version=version,
        )
    )


async def _seed_ioc(session, case_id: uuid.UUID, **kwargs) -> IOC:
    scored = make_scored_ioc(**kwargs)
    now = datetime.now(UTC)
    row = IOC(
        case_id=case_id,
        evidence_id=scored.attribution.evidence_id,
        ioc_type=scored.record.ioc_type,
        value=scored.record.value,
        raw_value=scored.record.raw_value,
        source=scored.record.source,
        confidence=scored.record.confidence,
        severity=scored.record.severity,
        classification=scored.classification.category,
        composite_score=scored.score.composite_score,
        rule_match_count=0,
        occurrence_count=1,
        extractor_name="test",
        extractor_version="1.0.0",
        status=IOCStatus.ACTIVE,
        metadata_json=scored.model_dump_json(),
        first_seen_at=now,
        last_seen_at=now,
    )
    repo = IOCRepository(session)
    await repo.add(row)
    return row


class _FakeCaseMemory:
    def __init__(self) -> None:
        self.notes: list[str] = []

    async def get_notes(self, case_id: uuid.UUID) -> list[str]:
        return self.notes

    async def add_note(self, case_id: uuid.UUID, note: str) -> None:
        self.notes.append(note)


@pytest.mark.unit
async def test_generate_findings_for_case_happy_path(
    database: Database, test_settings: Settings
) -> None:
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    events: list[FindingEvent] = []
    publisher = FindingEventPublisher()
    publisher.subscribe(events.append)
    case_memory = _FakeCaseMemory()

    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        pipeline = FindingGenerationPipeline(
            settings=test_settings, event_publisher=publisher, case_memory=case_memory
        )
        result = await generate_findings_for_case(
            session, case_id=case_id, settings=test_settings, pipeline=pipeline
        )
        await session.commit()

        assert result.case_id == case_id
        assert len(result.created_finding_ids) == 2  # T1110 + T1078

        repo = FindingRepository(session)
        persisted = await repo.find_by_case(case_id)
        assert len(persisted) == 2
        assert all(row.status is FindingStatus.OPEN for row in persisted)

    assert events
    assert any("Finding generation" in note for note in case_memory.notes)


@pytest.mark.unit
async def test_generate_findings_for_case_no_mappable_iocs_creates_nothing(
    database: Database, test_settings: Settings
) -> None:
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_ioc(session, case_id, ioc_type=IOCType.MUTEX, value="Global\\weird")
        await session.commit()

        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()

        assert result.created_finding_ids == ()
        assert result.candidate_count == 0


@pytest.mark.unit
async def test_second_run_merges_into_existing_finding(
    database: Database, test_settings: Settings
) -> None:
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        first = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()
        assert len(first.created_finding_ids) == 2

        # A second IOC of the same type, same case: the mapping engine
        # regenerates candidates for the *whole* active IOC set (both the
        # original and new IOC), so the new candidate's supporting IOCs
        # overlap heavily with the already-persisted Finding and should
        # merge rather than duplicate.
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        second = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()

        assert len(second.merged_finding_ids) == 2
        assert second.created_finding_ids == ()

        repo = FindingRepository(session)
        persisted = await repo.find_by_case(case_id)
        assert len(persisted) == 2  # still only 2 Findings — merged, not duplicated


@pytest.mark.unit
async def test_missing_technique_seed_degrades_without_crashing(
    database: Database, test_settings: Settings
) -> None:
    """No MitreTechnique reference rows seeded — persist() must still
    create the Finding row (join-table rows are skipped, logged, never a
    crash, per constitution §1.7)."""
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()

        assert len(result.created_finding_ids) == 2
        repo = FindingRepository(session)
        for finding_id in result.created_finding_ids:
            mappings = await repo.mappings_for_finding(finding_id)
            assert mappings == []


@pytest.mark.unit
async def test_dismissed_iocs_are_excluded_from_discovery(
    database: Database, test_settings: Settings
) -> None:
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        row = await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        ioc_repo = IOCRepository(session)
        await ioc_repo.mark_dismissed(row.id)
        await session.commit()

        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        assert result.candidate_count == 0


@pytest.mark.unit
async def test_get_finding_and_list_findings_for_case(
    database: Database, test_settings: Settings
) -> None:
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()

        finding_id = result.created_finding_ids[0]
        found = await get_finding(session, finding_id)
        assert found is not None

        listed = await list_findings_for_case(session, case_id)
        assert len(listed) == 2


@pytest.mark.unit
async def test_memory_notification_failure_never_breaks_generation(
    database: Database, test_settings: Settings
) -> None:
    class _BrokenCaseMemory:
        async def get_notes(self, case_id: uuid.UUID) -> list[str]:
            return []

        async def add_note(self, case_id: uuid.UUID, note: str) -> None:
            raise RuntimeError("memory backend unavailable")

    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await session.commit()

        pipeline = FindingGenerationPipeline(
            settings=test_settings, case_memory=_BrokenCaseMemory()
        )
        result = await generate_findings_for_case(
            session, case_id=case_id, settings=test_settings, pipeline=pipeline
        )
        assert len(result.created_finding_ids) == 2


@pytest.mark.unit
async def test_large_active_ioc_set_generates_findings_within_reasonable_time(
    database: Database, test_settings: Settings
) -> None:
    """Performance guard mirroring test_threat_intel_service's large-input
    test: a few hundred IOCs must generate/dedup/persist well under a few
    seconds — a regression guard against O(n^2) behavior in dedup."""
    from core.threat_intel.models import IOCType

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        await _seed_technique(session, "T1110", "Brute Force")
        await _seed_technique(session, "T1078", "Valid Accounts")
        for i in range(300):
            await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value=f"user{i}")
        await session.commit()

        started = time.monotonic()
        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()
        elapsed = time.monotonic() - started

    assert len(result.created_finding_ids) == 2
    assert elapsed < 15.0
