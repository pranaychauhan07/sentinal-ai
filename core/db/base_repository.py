"""Generic repository base class — the concrete implementation of the
``Repository`` Protocol (core/interfaces.py) for SQLAlchemy-backed models.

context/03_engineering_constitution.md §7: "Raw SQLAlchemy queries live
behind repository functions ... never inline inside an agent or a router."
No concrete repositories exist yet (there are no domain models until
Milestone M1, docs/roadmap.md) — this class is what every future
``CaseRepository``, ``EvidenceRepository``, etc. will subclass or wrap.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.session import Entity

ModelT = TypeVar("ModelT", bound=Entity)


class BaseRepository(Generic[ModelT]):
    """Generic async CRUD repository for a single ORM model.

    Bound to :class:`core.db.session.Entity` rather than the bare
    :class:`core.db.session.Base`, so every concrete model this repository
    can be constructed for is guaranteed (statically, not just by
    convention) to have the surrogate UUID ``id`` primary key
    (context/03_engineering_constitution.md §7, "Primary keys").
    """

    def __init__(self, session: AsyncSession, model: type[ModelT]) -> None:
        self._session = session
        self.model = model

    async def get_by_id(self, entity_id: Any) -> ModelT | None:
        return await self._session.get(self.model, entity_id)

    async def list(self, *, limit: int = 50, cursor: Any | None = None) -> list[ModelT]:
        """Cursor-based pagination ordered by primary key, matching the API
        Design pagination rule (context/03_engineering_constitution.md §6)."""
        stmt = select(self.model).order_by(self.model.id).limit(limit)
        if cursor is not None:
            stmt = stmt.where(self.model.id > cursor)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def add(self, entity: ModelT) -> ModelT:
        self._session.add(entity)
        await self._session.flush()
        return entity

    async def delete(self, entity_id: Any) -> None:
        instance = await self.get_by_id(entity_id)
        if instance is not None:
            await self._session.delete(instance)
            await self._session.flush()
