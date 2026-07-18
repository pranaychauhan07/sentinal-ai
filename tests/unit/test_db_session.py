"""Unit tests for core/db/session.py."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import Mapped

from core.config import Settings
from core.db.session import Base, Database, Entity, create_engine
from core.exceptions import InfrastructureError


class _Note(Entity):
    """Test-only model exercising Database.session()'s commit/rollback
    behavior — never imported outside this test module."""

    __tablename__ = "test_notes"

    text: Mapped[str]


@pytest.mark.unit
def test_create_engine_returns_async_engine(test_settings: Settings) -> None:
    engine = create_engine(test_settings)
    assert isinstance(engine, AsyncEngine)


@pytest.mark.unit
async def test_database_check_connection_succeeds_against_sqlite(
    test_settings: Settings,
) -> None:
    database = Database(test_settings)
    try:
        await database.check_connection()  # should not raise
    finally:
        await database.dispose()


@pytest.mark.unit
async def test_database_check_connection_fails_for_unreachable_path(
    test_settings: Settings, tmp_path
) -> None:
    broken_settings = test_settings.model_copy(
        update={"database_url": f"sqlite+aiosqlite:///{tmp_path}/missing_dir/test.db"}
    )
    database = Database(broken_settings)
    try:
        with pytest.raises(InfrastructureError):
            await database.check_connection()
    finally:
        await database.dispose()


@pytest.mark.unit
async def test_database_session_commits_on_success(test_settings: Settings) -> None:
    database = Database(test_settings)
    try:
        async with database.session_factory() as session:
            result = await session.execute(text("SELECT 1"))
            assert result.scalar_one() == 1
    finally:
        await database.dispose()


@pytest.mark.unit
async def test_database_session_generator_commits_on_success(test_settings: Settings) -> None:
    database = Database(test_settings)
    try:
        async with database.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async for session in database.session():
            session.add(_Note(text="hello"))

        async with database.session_factory() as verify_session:
            result = await verify_session.execute(select(_Note))
            assert result.scalar_one().text == "hello"
    finally:
        await database.dispose()


@pytest.mark.unit
async def test_database_session_generator_rolls_back_on_exception(
    test_settings: Settings,
) -> None:
    database = Database(test_settings)
    try:
        async with database.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        with pytest.raises(RuntimeError, match="boom"):
            async for session in database.session():
                session.add(_Note(text="should-not-persist"))
                await session.flush()
                raise RuntimeError("boom")

        async with database.session_factory() as verify_session:
            result = await verify_session.execute(select(_Note))
            assert result.scalars().all() == []
    finally:
        await database.dispose()
