"""Unit tests for core/memory/db_models.py + repository.py — the SQLite
persistence path, matching tests/unit/test_base_repository.py's pattern."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.models import MemoryQuery, MemoryRecord, MemoryScope
from core.memory.repository import MemoryRepository

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_save_and_get_record(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        record = MemoryRecord(scope=MemoryScope.CASE, key="note", content="first note")
        saved = await repo.save(record)
        await session.commit()

        fetched = await repo.get_record(saved.id)
        assert fetched is not None
        assert fetched.content == "first note"
        assert fetched.scope == MemoryScope.CASE


async def test_find_filters_by_scope(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        record_a = MemoryRecord(scope=MemoryScope.CASE, key="a", content="alpha")
        record_b = MemoryRecord(scope=MemoryScope.SESSION, key="b", content="beta")
        await repo.save(record_a)
        await repo.save(record_b)
        await session.commit()

        case_only = await repo.find(MemoryQuery(scope=MemoryScope.CASE))
        assert all(r.scope == MemoryScope.CASE for r in case_only)
        assert any(r.content == "alpha" for r in case_only)
        assert all(r.content != "beta" for r in case_only)


async def test_find_filters_by_text(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        await repo.save(MemoryRecord(scope=MemoryScope.CASE, key="k1", content="brute force login"))
        await repo.save(MemoryRecord(scope=MemoryScope.CASE, key="k2", content="phishing email"))
        await session.commit()

        matches = await repo.find(MemoryQuery(scope=MemoryScope.CASE, text="brute"))
        assert len(matches) == 1
        assert "brute" in matches[0].content


async def test_find_filters_by_tags(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        tagged = MemoryRecord(
            scope=MemoryScope.CASE, key="k", content="tagged", tags=("ioc", "high-priority")
        )
        untagged = MemoryRecord(scope=MemoryScope.CASE, key="k2", content="untagged")
        await repo.save(tagged)
        await repo.save(untagged)
        await session.commit()

        matches = await repo.find(MemoryQuery(scope=MemoryScope.CASE, tags=("ioc",)))
        assert len(matches) == 1
        assert matches[0].content == "tagged"


async def test_delete_expired_removes_only_past_expiry(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        expired = MemoryRecord(
            scope=MemoryScope.SESSION,
            key="expired",
            content="stale",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        alive = MemoryRecord(
            scope=MemoryScope.SESSION,
            key="alive",
            content="fresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await repo.save(expired)
        await repo.save(alive)
        await session.commit()

        deleted_count = await repo.delete_expired()
        await session.commit()

        assert deleted_count == 1
        remaining = await repo.find(MemoryQuery(scope=MemoryScope.SESSION))
        assert len(remaining) == 1
        assert remaining[0].content == "fresh"
