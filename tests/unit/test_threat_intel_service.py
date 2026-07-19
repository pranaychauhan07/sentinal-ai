"""Unit tests for core/services/threat_intel_service.py — the full
nine-stage IOCExtractionPipeline and its extract_threat_intelligence()
orchestrator."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.ioc_repository import IOCRepository
from core.db.models.ioc import IOCStatus
from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence
from core.services.threat_intel_service import (
    IOCExtractionPipeline,
    ThreatIntelExtractionResult,
    extract_threat_intelligence,
)
from core.threat_intel.events import ThreatIntelEvent, ThreatIntelEventPublisher
from core.threat_intel.models import (
    DetectionRule,
    IOCRecord,
    IOCType,
    RuleType,
    SourceReliability,
)
from core.threat_intel.rules import DetectionRuleEngine


class _FakeCaseMemory:
    def __init__(self) -> None:
        self.notes: list[str] = []

    async def get_notes(self, case_id: uuid.UUID) -> list[str]:
        return self.notes

    async def add_note(self, case_id: uuid.UUID, note: str) -> None:
        self.notes.append(note)


class _BrokenCaseMemory:
    async def get_notes(self, case_id: uuid.UUID) -> list[str]:
        return []

    async def add_note(self, case_id: uuid.UUID, note: str) -> None:
        raise RuntimeError("memory backend unavailable")


def _make_evidence(*raw_lines: str) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=EvidenceType.PLAIN_TEXT,
        source="test.log",
        parser_name="plain_text",
        parser_version="1.0.0",
        confidence=0.9,
        records=[
            EvidenceRecord(raw_line=line, line_number=i)
            for i, line in enumerate(raw_lines, start=1)
        ],
        chain_of_custody=ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by="tester",
            original_filename="test.log",
            sha256="a" * 64,
            file_size_bytes=len("".join(raw_lines)),
        ),
    )


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


@pytest.mark.unit
async def test_extract_threat_intelligence_happy_path_persists_iocs(
    database: Database, test_settings: Settings
) -> None:
    case_id = uuid.uuid4()
    events: list[ThreatIntelEvent] = []
    publisher = ThreatIntelEventPublisher()
    publisher.subscribe(events.append)
    case_memory = _FakeCaseMemory()

    pipeline = IOCExtractionPipeline(
        settings=test_settings, event_publisher=publisher, case_memory=case_memory
    )
    evidence = _make_evidence("failed login from 10.0.0.5 for user admin")

    async with database.session_factory() as session:
        result = await extract_threat_intelligence(
            session, case_id=case_id, evidence=evidence, settings=test_settings, pipeline=pipeline
        )
        await session.commit()

        assert isinstance(result, ThreatIntelExtractionResult)
        assert result.ioc_count >= 1
        assert any(
            scored.record.ioc_type == IOCType.IPV4 and scored.record.value == "10.0.0.5"
            for scored in result.normalized_threat_intel.iocs
        )

        repo = IOCRepository(session)
        persisted = await repo.find_by_case(case_id)
        assert len(persisted) == result.ioc_count
        assert all(row.status == IOCStatus.ACTIVE for row in persisted)

    assert events  # at least one CLASSIFIED/DEGRADED event published
    assert any("IOC extraction" in note for note in case_memory.notes)


@pytest.mark.unit
async def test_extract_threat_intelligence_with_matching_detection_rule(
    database: Database, test_settings: Settings
) -> None:
    rule_engine = DetectionRuleEngine()
    rule_engine.register_rule(
        DetectionRule(
            rule_id="known-bad-ip",
            name="known bad IP",
            rule_type=RuleType.PATTERN,
            pattern="10.0.0.5",
            ioc_types=(IOCType.IPV4,),
        )
    )
    pipeline = IOCExtractionPipeline(settings=test_settings, rule_engine=rule_engine)
    evidence = _make_evidence("connection from 10.0.0.5 established")

    async with database.session_factory() as session:
        result = await extract_threat_intelligence(
            session,
            case_id=uuid.uuid4(),
            evidence=evidence,
            settings=test_settings,
            pipeline=pipeline,
            source_reliability=SourceReliability.HIGH,
        )
        scored = next(
            s for s in result.normalized_threat_intel.iocs if s.record.value == "10.0.0.5"
        )
        assert scored.classification.category.value in ("suspicious", "malicious")
        assert scored.rule_matches


@pytest.mark.unit
async def test_extract_threat_intelligence_records_rejected_candidates(
    database: Database, test_settings: Settings
) -> None:
    """A malformed candidate (e.g. an out-of-range port from a stray regex
    match) must be recorded, never silently dropped without a trace."""
    pipeline = IOCExtractionPipeline(settings=test_settings)
    evidence = _make_evidence("connection on port=99999 was blocked")

    async with database.session_factory() as session:
        result = await extract_threat_intelligence(
            session,
            case_id=uuid.uuid4(),
            evidence=evidence,
            settings=test_settings,
            pipeline=pipeline,
        )
        assert result.rejected_count >= 1
        assert result.normalized_threat_intel.rejected_candidates


@pytest.mark.unit
async def test_memory_notification_failure_never_breaks_extraction(
    database: Database, test_settings: Settings
) -> None:
    pipeline = IOCExtractionPipeline(settings=test_settings, case_memory=_BrokenCaseMemory())
    evidence = _make_evidence("connection from 10.0.0.5 established")

    async with database.session_factory() as session:
        result = await extract_threat_intelligence(
            session,
            case_id=uuid.uuid4(),
            evidence=evidence,
            settings=test_settings,
            pipeline=pipeline,
        )
        assert result.ioc_count >= 1


@pytest.mark.unit
def test_deduplicate_stage_caps_total_ioc_count(test_settings: Settings) -> None:
    test_settings.threat_intel_max_iocs_per_artifact = 2
    pipeline = IOCExtractionPipeline(settings=test_settings)
    candidates = [_candidate(f"{i}.{i}.{i}.{i}") for i in range(1, 6)]
    kept, truncated = pipeline.deduplicate(candidates)
    assert len(kept) == 2
    assert truncated == 3


def _candidate(value: str) -> IOCRecord:
    return IOCRecord(ioc_type=IOCType.IPV4, value=value, raw_value=value, source="test")


@pytest.mark.unit
def test_discover_stage_uses_default_extractor(test_settings: Settings) -> None:
    pipeline = IOCExtractionPipeline(settings=test_settings)
    evidence = _make_evidence("beacon to evil.example.com")
    candidates = pipeline.discover(evidence)
    assert any(c.ioc_type == IOCType.DOMAIN for c in candidates)


@pytest.mark.unit
async def test_large_evidence_artifact_extracts_within_reasonable_time(
    database: Database, test_settings: Settings
) -> None:
    """Performance guard: a few thousand log lines with scattered IOCs must
    extract well under a few seconds — a regression guard against
    accidental O(n^2) behavior in dedup/attribution."""
    lines = [
        f"login attempt from 10.0.{i % 255}.{(i * 7) % 255} for user user{i % 50}"
        for i in range(3000)
    ]
    evidence = _make_evidence(*lines)
    pipeline = IOCExtractionPipeline(settings=test_settings)

    async with database.session_factory() as session:
        started = time.monotonic()
        result = await extract_threat_intelligence(
            session,
            case_id=uuid.uuid4(),
            evidence=evidence,
            settings=test_settings,
            pipeline=pipeline,
        )
        elapsed = time.monotonic() - started

    assert result.ioc_count > 0
    assert elapsed < 15.0
