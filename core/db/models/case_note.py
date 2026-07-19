"""`CaseNote` — editable analyst commentary attached to a `Case` (ADR-0015
point 2), distinct from `TimelineEvent.MANUAL_NOTE`: `TimelineEvent` is an
immutable audit record ("a note was added/changed/removed, by whom, when");
`CaseNote` is the mutable content itself. Every create/update/delete of a
`CaseNote` (`core/services/case_service.py`) records a paired
`TimelineEvent(event_type=MANUAL_NOTE)` so the audit trail never silently
diverges from what actually happened to a note.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class CaseNote(Entity):
    __tablename__ = "case_notes"
    __table_args__ = (Index("ix_case_notes_case_id", "case_id"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: Placeholder string column, matching `Case.analyst_id`'s shape — the
    #: analyst who authored/last-edited this note.
    author_id: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
