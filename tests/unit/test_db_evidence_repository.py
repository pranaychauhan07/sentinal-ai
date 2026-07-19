"""Unit tests for core/db/models/evidence.py + core/db/evidence_repository.py
— real SQLite, mirroring tests/unit/test_base_repository.py's pattern."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.evidence_repository import EvidenceRepository
from core.db.models.evidence import Evidence, EvidenceStatus
from core.parsers.models import EvidenceType


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _make_evidence(case_id: uuid.UUID, *, sha256: str = "a" * 64) -> Evidence:
    return Evidence(
        case_id=case_id,
        evidence_type=EvidenceType.SSH_AUTH,
        original_filename="ssh_auth.log",
        storage_ref="/tmp/ssh_auth.log",
        sha256=sha256,
        file_size_bytes=100,
        mime_type="text/plain",
        encoding="utf-8",
        uploaded_at=datetime.now(UTC),
    )


@pytest.mark.unit
async def test_add_and_get_by_id(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        created = await repo.add(_make_evidence(case_id))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.status == EvidenceStatus.UPLOADED
        assert fetched.case_id == case_id


@pytest.mark.unit
async def test_find_by_case_scopes_to_case_id(database: Database) -> None:
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        await repo.add(_make_evidence(case_a, sha256="a" * 64))
        await repo.add(_make_evidence(case_a, sha256="b" * 64))
        await repo.add(_make_evidence(case_b, sha256="c" * 64))
        await session.commit()

        results = await repo.find_by_case(case_a)
        assert len(results) == 2
        assert all(e.case_id == case_a for e in results)


@pytest.mark.unit
async def test_find_by_sha256_returns_none_when_absent(database: Database) -> None:
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        assert await repo.find_by_sha256("nonexistent") is None


@pytest.mark.unit
async def test_find_by_sha256_detects_duplicate_upload(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        created = await repo.add(_make_evidence(case_id, sha256="d" * 64))
        await session.commit()

        found = await repo.find_by_sha256("d" * 64)
        assert found is not None
        assert found.id == created.id


@pytest.mark.unit
async def test_mark_parsed_updates_status_and_confidence(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        created = await repo.add(_make_evidence(case_id))
        await session.commit()

        updated = await repo.mark_parsed(
            created.id,
            parser_name="ssh_auth",
            parser_version="1.0.0",
            parser_confidence=0.95,
            parsed_json="{}",
        )
        await session.commit()

        assert updated is not None
        assert updated.status == EvidenceStatus.PARSED
        assert updated.parser_confidence == 0.95
        assert updated.parsed_at is not None


@pytest.mark.unit
async def test_mark_failed_updates_status_and_error(database: Database) -> None:
    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        created = await repo.add(_make_evidence(case_id))
        await session.commit()

        updated = await repo.mark_failed(created.id, error_message="boom")
        await session.commit()

        assert updated is not None
        assert updated.status == EvidenceStatus.FAILED
        assert updated.error_message == "boom"


@pytest.mark.unit
async def test_mark_parsed_on_missing_id_returns_none(database: Database) -> None:
    async with database.session_factory() as session:
        repo = EvidenceRepository(session)
        result = await repo.mark_parsed(
            uuid.uuid4(),
            parser_name="ssh_auth",
            parser_version="1.0.0",
            parser_confidence=1.0,
            parsed_json="{}",
        )
        assert result is None
