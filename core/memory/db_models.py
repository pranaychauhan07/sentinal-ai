"""SQLAlchemy persistence model for `MemoryRecord` (`core/memory/models.py`).

`core/memory` is one of the leaf layers docs/dependency-rules.md rule 6/7
treats analogously to `core/db` for its own persistence needs: it owns a
narrow table for memory data (case notes, long-term retrieval metadata) the
same way `core/db` owns the future domain schema — this module, not any
agent or service, is where the Pydantic-to-ORM translation happens
(constitution §7). No domain (`Case`/`Evidence`/`Finding`) model is
referenced or required here; `case_id` is stored as a plain UUID column, not
a foreign key, because those tables don't exist yet (Milestone M1) and this
layer must not block on them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.memory.models import MemoryPriority, MemoryScope


class MemoryRecordRow(Entity):
    """ORM row backing one persisted `MemoryRecord`.

    Indexed on `(scope, case_id)` — the exact filter `MemoryRepository`'s
    query helpers use — per constitution §7's "every column used in a WHERE
    ... is indexed."
    """

    __tablename__ = "memory_records"
    __table_args__ = (Index("ix_memory_records_scope_case_id", "scope", "case_id"),)

    scope: Mapped[str] = mapped_column(String(32))
    case_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    key: Mapped[str] = mapped_column(String(256))
    content: Mapped[str]
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    priority: Mapped[str] = mapped_column(String(16), default=MemoryPriority.NORMAL.value)
    record_metadata: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)

    @property
    def scope_enum(self) -> MemoryScope:
        return MemoryScope(self.scope)
