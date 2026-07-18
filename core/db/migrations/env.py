"""Alembic environment, wired to this project's async engine and settings
(core/config/settings.py) rather than a second, hand-maintained
``sqlalchemy.url`` in ``alembic.ini`` — see core/db/migrations/README.md and
docs/adr/0004-relational-database.md.

No domain models are imported into ``target_metadata`` yet — there are none
until Milestone M1 (docs/roadmap.md). Once ``core/db/models.py`` exists, add
``from core.db import models  # noqa: F401`` below so Alembic's autogenerate
can see them via ``Base.metadata``.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine

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
