"""Unit tests for core/db/base_repository.py.

Uses a throwaway ORM model defined only in this test module (never imported
elsewhere) to exercise the generic repository against a real schema, since
no domain models exist yet (docs/roadmap.md Milestone M1).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.orm import Mapped

from core.config import Settings
from core.db import Base, BaseRepository, Database, Entity


class _Widget(Entity):
    """Test-only model — proves BaseRepository against a real table without
    depending on any not-yet-implemented domain model. Inherits the
    surrogate UUID ``id`` primary key from :class:`core.db.Entity`."""

    __tablename__ = "test_widgets"

    name: Mapped[str]


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


@pytest.mark.unit
async def test_add_and_get_by_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = BaseRepository(session, _Widget)
        created = await repo.add(_Widget(name="first"))
        await session.commit()

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.name == "first"


@pytest.mark.unit
async def test_get_by_id_returns_none_when_missing(database: Database) -> None:
    async with database.session_factory() as session:
        repo = BaseRepository(session, _Widget)
        assert await repo.get_by_id(uuid.uuid4()) is None


@pytest.mark.unit
async def test_list_respects_limit_and_cursor(database: Database) -> None:
    """Cursor pagination is exercised for stability/no-duplication, not for
    insertion order — the surrogate key is a random UUID
    (context/03_engineering_constitution.md §7), so ``id`` ordering is a
    valid, deterministic total order but not a chronological one."""
    async with database.session_factory() as session:
        repo = BaseRepository(session, _Widget)
        for name in ("a", "b", "c"):
            await repo.add(_Widget(name=name))
        await session.commit()

        first_page = await repo.list(limit=2)
        assert len(first_page) == 2

        second_page = await repo.list(limit=2, cursor=first_page[-1].id)
        assert len(second_page) == 1

        all_ids = {w.id for w in first_page} | {w.id for w in second_page}
        assert len(all_ids) == 3  # every item returned exactly once across pages


@pytest.mark.unit
async def test_delete_removes_entity(database: Database) -> None:
    async with database.session_factory() as session:
        repo = BaseRepository(session, _Widget)
        created = await repo.add(_Widget(name="to-delete"))
        await session.commit()

        await repo.delete(created.id)
        await session.commit()

        assert await repo.get_by_id(created.id) is None


@pytest.mark.unit
async def test_delete_missing_entity_is_a_no_op(database: Database) -> None:
    async with database.session_factory() as session:
        repo = BaseRepository(session, _Widget)
        await repo.delete(uuid.uuid4())  # should not raise
