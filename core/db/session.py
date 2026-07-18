"""Async SQLAlchemy engine/session management — the Database Layer's
connection-handling foundation (context/01_blueprint.md §4,
docs/adr/0004-relational-database.md).

No domain models are defined yet (Case/Evidence/Finding arrive with the
first real agents, docs/roadmap.md Milestone M1) — this module only
establishes the engine, session factory, declarative base, and a
connectivity health check every future model/repository builds on.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from core.config import Settings
from core.exceptions import InfrastructureError
from core.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base every ORM model in ``core/db`` inherits from.

    A single shared base is required for Alembic's autogeneration
    (``core/db/migrations/env.py``) to discover all models via
    ``Base.metadata``.
    """


class Entity(Base):
    """Abstract base providing the surrogate UUID primary key every domain
    table uses (context/03_engineering_constitution.md §7, "Primary keys":
    "every table has a surrogate primary key (id, UUID), never a natural
    key"). Concrete models (``Case``, ``Evidence``, ``Finding``, ...) inherit
    from this instead of ``Base`` directly; ``core/db/base_repository.py``'s
    generic repository is bound to this type precisely so ``.id`` is always
    statically known to exist.
    """

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


def create_engine(settings: Settings) -> AsyncEngine:
    """Build the async engine for the configured ``DATABASE_URL``.

    Works identically against the SQLite fallback and PostgreSQL
    (docs/adr/0004-relational-database.md) — callers never branch on dialect.
    """
    engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if settings.is_sqlite:
        # SQLite has no real connection pool semantics; NullPool avoids
        # "database is locked" errors under concurrent async access in dev/test.
        from sqlalchemy.pool import NullPool

        engine_kwargs["poolclass"] = NullPool

    return create_async_engine(settings.database_url, **engine_kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build the session factory bound to ``engine``."""
    return async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


class Database:
    """Owns one engine + session factory for the lifetime of the
    application process. Constructed once in the FastAPI lifespan
    (apps/api/main.py) and injected via dependency, never imported as a
    module-level global instance (context/03_engineering_constitution.md §2,
    "avoid global state")."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.engine = create_engine(settings)
        self.session_factory = create_session_factory(self.engine)

    async def dispose(self) -> None:
        """Close all pooled connections. Called from the FastAPI lifespan
        shutdown phase."""
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a request/task-scoped session, committing on success and
        rolling back on any exception."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def check_connection(self) -> None:
        """Raise :class:`InfrastructureError` if the database is not
        reachable. Used by the ``/ready`` endpoint
        (apps/api/routers/system.py) — never called from request-handling
        paths that don't specifically need a liveness/readiness signal."""
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001 - intentionally broad: any DB failure means "not ready"
            logger.error("database_connection_check_failed", error=str(exc))
            raise InfrastructureError(
                "Database connection check failed.", details={"reason": str(exc)}
            ) from exc
