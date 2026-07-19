"""`Report` — blueprint §8's schema-only placeholder for this milestone: the
table and its columns exist so `Case`'s full owned-entity set matches the
blueprint exactly, but no report is ever generated yet (`file_path`/
`generated_at` stay `NULL` until the Report Generator Agent, Milestone M5,
`docs/roadmap.md`). No API route or service function reads/writes this table
this session — creating one now with nothing to call it would be exactly the
placeholder logic constitution §8 forbids.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class ReportType(StrEnum):
    """blueprint §10 ("Report Generator Agent... module-level + case-level
    executive PDF reports")."""

    MODULE = "module"
    EXECUTIVE = "executive"


class Report(Entity):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_case_id", "case_id"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    report_type: Mapped[ReportType] = mapped_column(
        SqlEnum(
            ReportType, name="report_type_enum", values_callable=lambda e: [x.value for x in e]
        ),
        nullable=False,
    )
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(nullable=True)
