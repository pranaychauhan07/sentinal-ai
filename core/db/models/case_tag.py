"""`CaseTag` — a filterable, indexed tag attached to a `Case` (ADR-0015
point 5). Modeled as a join table rather than a Postgres-only `ARRAY` column
or an unindexed JSON blob, so tag filtering works identically against the
SQLite fallback and PostgreSQL (blueprint §4). Distinct from `Case.labels`,
which is freeform, unindexed key->value metadata, not meant to be queried.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class CaseTag(Entity):
    __tablename__ = "case_tags"
    __table_args__ = (
        Index("ix_case_tags_case_id", "case_id"),
        Index("ix_case_tags_tag", "tag"),
        UniqueConstraint("case_id", "tag", name="uq_case_tags_case_id_tag"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    tag: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
