"""FastAPI dependency providers.

Every router depends on these functions rather than reaching for global
state directly — context/03_engineering_constitution.md §2 ("dependency
injection", "avoid global state").
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings, get_settings
from core.db import Database


def get_settings_dependency() -> Settings:
    """FastAPI dependency wrapper around :func:`core.config.get_settings`."""
    return get_settings()


def get_database(request: Request) -> Database:
    """Return the process-wide :class:`core.db.Database` instance created in
    the application lifespan (apps/api/main.py) and stored on ``app.state``."""
    return request.app.state.database  # type: ignore[no-any-return]


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped database session, committing on success and
    rolling back on failure (core/db/session.py:Database.session)."""
    database: Database = request.app.state.database
    async for session in database.session():
        yield session


class AuthenticatedUser(BaseModel):
    """Placeholder authenticated-user shape.

    context/03_engineering_constitution.md §6 ("Authentication readiness"):
    every router depends on ``get_current_user`` from day one so real
    authentication is a dependency swap later, not a router rewrite. No real
    auth/User persistence exists yet (blueprint §8's ``User`` table arrives
    with multi-user support — blueprint §17, Future Expansion).
    """

    id: str
    display_name: str


def get_current_user() -> AuthenticatedUser:
    """Fixed default user until real authentication is implemented.

    Deliberately not configurable via settings — a single, obvious, greppable
    placeholder rather than a "temporary" value that quietly becomes load
    bearing.
    """
    return AuthenticatedUser(id="local-analyst", display_name="Default Analyst")


# Reusable `Annotated` dependency aliases — every current and future router
# imports these rather than repeating `Depends(...)` in its own signature
# (avoids the `Depends()`-as-default-argument anti-pattern and keeps the
# dependency wiring for a given contract in exactly one place).
SettingsDep = Annotated[Settings, Depends(get_settings_dependency)]
DatabaseDep = Annotated[Database, Depends(get_database)]
DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUserDep = Annotated[AuthenticatedUser, Depends(get_current_user)]
