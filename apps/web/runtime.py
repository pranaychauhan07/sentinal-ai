"""Streamlit's async/DB bootstrap — the sync-framework equivalent of
`apps/api/main.py`'s lifespan + `apps/api/dependencies.py`'s session
provider (context/01_blueprint.md §4: "Streamlit calls the same
`services/` Python functions... in-process at first").

This module is infrastructure wiring, not business logic (constitution §3,
docs/dependency-rules.md rule 3: "apps/web pages/components contain no
business logic ... call exactly one `core/services` function per user
action"). Every page imports `run_async`/`session_scope`/`get_settings` from
here instead of constructing its own `Database`/event loop — the same
"one place this is wired" discipline `apps/api/dependencies.py` already
established for the API layer.

Streamlit reruns the whole script top-to-bottom on every interaction and has
no native `async def` page support, so each page awaits its `core/services`
call via `run_async` (a fresh `asyncio.run()` per call — simple, correct,
and cheap enough at this app's interactive, one-user-click-at-a-time request
volume; a persistent event loop would need a background thread and buys
nothing here).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TypeVar

import streamlit as st
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings, get_settings
from core.db import Database

_T = TypeVar("_T")


@st.cache_resource
def get_settings_cached() -> Settings:
    """Process-wide settings, cached across Streamlit reruns (constitution
    §2's documented-singleton exception — `st.cache_resource` is Streamlit's
    own sanctioned mechanism for exactly this, the same role
    `functools.lru_cache` plays for `core.config.get_settings`)."""
    return get_settings()


@st.cache_resource
def get_database() -> Database:
    """One `Database` (engine + session factory) for the life of the
    Streamlit process — mirrors `apps/api/main.py`'s `_lifespan` constructing
    exactly one `Database` and storing it on `app.state`."""
    return Database(get_settings_cached())


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """A request-scoped session that commits on success and rolls back on
    failure — the identical contract `apps/api/dependencies.py`'s
    `get_db_session` provides via `Database.session()`, reused here rather
    than reimplemented (constitution §14.9)."""
    database = get_database()
    async for session in database.session():
        yield session


def run_async(coro_factory: Callable[[AsyncSession], Awaitable[_T]]) -> _T:
    """Runs one `core/services` call to completion inside a fresh event
    loop, opening and closing its own DB session. `coro_factory` receives the
    session rather than the caller opening one itself, so `session_scope`'s
    commit/rollback always wraps exactly the work being awaited — a page
    can never accidentally read/write outside a managed transaction."""

    async def _run() -> _T:
        async with session_scope() as session:
            return await coro_factory(session)

    return asyncio.run(_run())
