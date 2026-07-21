"""Integration test for ADR-0027's long-term-memory write path
(`core.services.case_service._record_long_term_memory`) and its cross-case
read path (`core.memory.long_term.LongTermMemoryManager.
find_similar_excluding_case`) — a real case investigation, against a real
temp-directory ChromaDB (via `test_settings`'s `CHROMA_PERSIST_DIR`), then a
second case querying for "similar past investigations." Mirrors
tests/integration/test_case_service_pipeline.py's "real data, not hand-built
fixtures" pattern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.db import Base, Database
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.memory.manager import default_long_term_memory
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


async def test_investigation_writes_findings_into_long_term_memory(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="SSH brute force - long-term memory write", analyst_id="local-analyst"
        )
        await session.commit()

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

    assert result.created_finding_ids

    memory = default_long_term_memory()
    hits = await memory.find_similar("brute force")
    assert len(hits) > 0
    assert any(hit.case_id == case.id for hit in hits)


async def test_similar_past_investigation_surfaces_across_cases(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case_a = await case_service.create_case(
            session, title="SSH brute force - case A", analyst_id="local-analyst"
        )
        await session.commit()
    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case_a.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    async with database.session_factory() as session:
        case_b = await case_service.create_case(
            session, title="SSH brute force - case B", analyst_id="local-analyst"
        )
        await session.commit()

    memory = default_long_term_memory()
    results = await memory.find_similar_excluding_case(
        "brute force ssh login failures", exclude_case_id=case_b.id
    )
    assert len(results) > 0
    assert all(result.case_id != case_b.id for result in results)
    assert any(result.case_id == case_a.id for result in results)


async def test_deleting_long_term_memory_for_a_case_removes_its_vectors(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="SSH brute force - deletion test", analyst_id="local-analyst"
        )
        await session.commit()
    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    memory = default_long_term_memory()
    assert await memory.find_similar_in_case("brute force", case_id=case.id)

    await memory.delete_case(case.id)
    assert await memory.find_similar_in_case("brute force", case_id=case.id) == []
