"""Integration test for the graph-integrated Memory Agent (ADR-0028): a real
case investigation against a real temp-directory ChromaDB, followed by a
second case whose own investigation surfaces the first case's findings via
`MemoryAgent`'s output — the read half of blueprint §9's "Memory Agent
(read)" step, now automatic on every evidence upload. Mirrors
tests/integration/test_case_service_long_term_memory.py's "real data, not
hand-built fixtures" pattern exactly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.db import Base, Database
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


async def test_memory_agent_runs_on_a_cases_first_ever_upload(
    database: Database, test_settings: Settings
) -> None:
    """The very first case investigated has no prior *case* to find yet, but
    the Memory Agent still runs (it is cross-cutting, ADR-0028 §4) and
    reports a real, non-`None` count — a documented "queried, found
    nothing new" outcome, never silently skipped. Asserted as "not None"
    rather than "== 0": the Memory Agent's item count also includes
    Knowledge Layer document matches, whose availability depends on
    process-wide knowledge-source registration (`core.knowledge.bootstrap.
    register_default_knowledge_sources`) that this test does not control and
    other tests in the same pytest session may have already triggered — the
    invariant this test actually verifies is "the agent ran and produced a
    typed count," not "the Knowledge Layer is empty in this process."."""
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="SSH brute force - memory agent first upload", analyst_id="local-analyst"
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

    assert result.memory_context_item_count is not None
    assert result.memory_similar_finding_count == 0


async def test_memory_agent_surfaces_a_prior_cases_findings(
    database: Database, test_settings: Settings
) -> None:
    """A second case investigating the same kind of evidence surfaces the
    first case's already-recorded findings/report through `MemoryAgent`'s
    resolved `MemoryContext` — the concrete "have we seen this before?"
    blueprint §7 describes."""
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case_a = await case_service.create_case(
            session, title="SSH brute force - memory agent case A", analyst_id="local-analyst"
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
            session, title="SSH brute force - memory agent case B", analyst_id="local-analyst"
        )
        await session.commit()
    async with database.session_factory() as session:
        result_b = await case_service.investigate_new_evidence(
            session,
            case_id=case_b.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    assert result_b.memory_similar_finding_count is not None
    assert result_b.memory_similar_finding_count > 0
