"""Unit tests for core/memory/lifecycle.py."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from core.config import Settings
from core.db import Base, Database
from core.memory.lifecycle import DEFAULT_RETENTION, MemoryLifecycleManager
from core.memory.models import MemoryRecord, MemoryScope
from core.memory.repository import MemoryRepository

pytestmark = pytest.mark.unit


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_cleanup_expired_deletes_only_expired_records(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        expired = MemoryRecord(
            scope=MemoryScope.SESSION,
            key="e",
            content="old",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        alive = MemoryRecord(scope=MemoryScope.SESSION, key="a", content="new")
        await repo.save(expired)
        await repo.save(alive)
        await session.commit()

        manager = MemoryLifecycleManager(repo)
        report = await manager.cleanup_expired()
        await session.commit()

        assert report.records_deleted == 1
        assert report.scope is None


async def test_cleanup_expired_can_be_scoped(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MemoryRepository(session)
        await repo.save(
            MemoryRecord(
                scope=MemoryScope.SESSION,
                key="e",
                content="old",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )
        await repo.save(
            MemoryRecord(
                scope=MemoryScope.CASE,
                key="e2",
                content="old case note",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )
        await session.commit()

        manager = MemoryLifecycleManager(repo)
        report = await manager.cleanup_expired(scope=MemoryScope.SESSION)
        await session.commit()

        assert report.records_deleted == 1
        assert report.scope == MemoryScope.SESSION


def test_default_expiry_for_uses_configured_retention() -> None:
    now = datetime.now(UTC)
    expiry = MemoryLifecycleManager.default_expiry_for(MemoryScope.SESSION, now=now)
    assert expiry == now + DEFAULT_RETENTION[MemoryScope.SESSION]


def test_default_expiry_for_differs_per_scope() -> None:
    now = datetime.now(UTC)
    session_expiry = MemoryLifecycleManager.default_expiry_for(MemoryScope.SESSION, now=now)
    case_expiry = MemoryLifecycleManager.default_expiry_for(MemoryScope.CASE, now=now)
    assert session_expiry < case_expiry
