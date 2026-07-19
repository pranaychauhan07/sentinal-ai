"""Unit tests for core/services/evidence_service.py — the full ten-stage
EvidencePipeline and its ingest_evidence() orchestrator."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.evidence_repository import EvidenceRepository
from core.db.models.evidence import EvidenceStatus
from core.parsers.events import ParserEvent, ParserEventPublisher
from core.parsers.exceptions import FileTooLargeError, UnsupportedFormatError
from core.services import evidence_service
from core.services.evidence_service import (
    EvidenceIngestionResult,
    EvidencePipeline,
    ingest_evidence,
)

SSH_AUTH_FIXTURE = Path("data/sample_evidence/ssh_auth.log")


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


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


@pytest.mark.unit
async def test_ingest_evidence_happy_path_persists_and_returns_result(
    database: Database, test_settings: Settings
) -> None:
    case_id = uuid.uuid4()
    events: list[ParserEvent] = []
    publisher = ParserEventPublisher()
    publisher.subscribe(events.append)
    case_memory = _FakeCaseMemory()

    pipeline = EvidencePipeline(
        settings=test_settings,
        event_publisher=publisher,
        case_memory=case_memory,
        ingested_by="analyst-1",
    )

    async with database.session_factory() as session:
        result = await ingest_evidence(
            session,
            case_id=case_id,
            filename="ssh_auth.log",
            content=SSH_AUTH_FIXTURE.read_bytes(),
            settings=test_settings,
            pipeline=pipeline,
        )
        await session.commit()

        assert isinstance(result, EvidenceIngestionResult)
        assert result.status == EvidenceStatus.PARSED
        assert result.confidence == 1.0
        assert result.normalized_evidence.record_count == 20

        repo = EvidenceRepository(session)
        persisted = await repo.get_by_id(result.evidence_id)
        assert persisted is not None
        assert persisted.case_id == case_id
        assert persisted.parser_name == "ssh_auth"
        assert Path(persisted.storage_ref).exists()

    assert any(e.event_type.value == "parsed" for e in events)
    assert any("ingested" in note for note in case_memory.notes)


@pytest.mark.unit
async def test_ingest_evidence_rejects_oversized_upload_without_persisting(
    database: Database, test_settings: Settings
) -> None:
    test_settings.evidence_max_upload_bytes = 10
    case_id = uuid.uuid4()

    async with database.session_factory() as session:
        with pytest.raises(FileTooLargeError):
            await ingest_evidence(
                session,
                case_id=case_id,
                filename="ssh_auth.log",
                content=b"x" * 100,
                settings=test_settings,
            )

        repo = EvidenceRepository(session)
        assert await repo.find_by_case(case_id) == []


@pytest.mark.unit
async def test_ingest_evidence_rejects_disallowed_extension(
    database: Database, test_settings: Settings
) -> None:
    async with database.session_factory() as session:
        with pytest.raises(UnsupportedFormatError):
            await ingest_evidence(
                session,
                case_id=uuid.uuid4(),
                filename="payload.exe",
                content=b"MZ\x90\x00",
                settings=test_settings,
            )


@pytest.mark.unit
async def test_memory_notification_failure_never_breaks_ingestion(
    database: Database, test_settings: Settings
) -> None:
    """ADR-0006's "memory is always advisory" contract, exercised for the
    first time by evidence ingestion: a broken CaseMemory must not prevent a
    successful, persisted ingestion result."""
    pipeline = EvidencePipeline(settings=test_settings, case_memory=_BrokenCaseMemory())

    async with database.session_factory() as session:
        result = await ingest_evidence(
            session,
            case_id=uuid.uuid4(),
            filename="ssh_auth.log",
            content=SSH_AUTH_FIXTURE.read_bytes(),
            settings=test_settings,
            pipeline=pipeline,
        )
        assert result.status == EvidenceStatus.PARSED


@pytest.mark.unit
def test_normalize_stage_caps_record_count(
    test_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime

    from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence

    monkeypatch.setattr(evidence_service, "MAX_RECORDS_PER_ARTIFACT", 3)
    pipeline = EvidencePipeline(settings=test_settings)
    custody = ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="big.log",
        sha256="0" * 64,
        file_size_bytes=1,
    )
    normalized = NormalizedEvidence(
        evidence_type=EvidenceType.SYSLOG,
        source="big.log",
        parser_name="syslog",
        parser_version="1.0.0",
        confidence=1.0,
        records=[EvidenceRecord(raw_line=str(i)) for i in range(10)],
        chain_of_custody=custody,
    )

    capped = pipeline.normalize(normalized)
    assert len(capped.records) == 3
    assert capped.metadata["truncated_records"] == 7


@pytest.mark.unit
def test_upload_stage_sanitizes_filename(test_settings: Settings) -> None:
    pipeline = EvidencePipeline(settings=test_settings, ingested_by="analyst-1")
    raw = pipeline.upload("evidence.log", b"content")
    assert raw.ingested_by == "analyst-1"
    assert raw.content == b"content"
