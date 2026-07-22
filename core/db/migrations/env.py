"""Alembic environment, wired to this project's async engine and settings
(core/config/settings.py) rather than a second, hand-maintained
``sqlalchemy.url`` in ``alembic.ini`` — see core/db/migrations/README.md and
docs/adr/0004-relational-database.md.

``core.db.models`` is imported for its side effect of registering every
domain table onto ``Base.metadata`` before autogeneration inspects it — a
new domain module (Milestone M1's ``Case``/``Finding``/etc.) only needs to
be imported from ``core/db/models/__init__.py``, not from here.

``core.memory``'s own persistence submodules (``db_models.py``,
``conversation_db_models.py``) are imported here too, for the identical
reason: ``core/memory`` owns a narrow slice of the schema
(``memory_records``, ``conversation_sessions``/``conversation_messages``/
``conversation_summaries``) the same way ``core/db`` owns the domain schema
(docs/adr/0029-conversation-persistence-compression-export.md Decision 1) —
both need to be on ``Base.metadata`` for autogeneration to see them.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine

import core.db.models  # noqa: F401 - registers domain tables onto Base.metadata
import core.memory.conversation_db_models  # noqa: F401 - registers conversation tables
import core.memory.db_models  # noqa: F401 - registers the memory_records table
from core.config import get_settings
from core.db.session import Base, create_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (emits SQL to stdout)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Any) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live async engine, matching the same engine
    construction used by the application (core/db/session.py) so migrations
    are validated against the identical driver/dialect configuration."""
    connectable: AsyncEngine = create_engine(get_settings())

    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
