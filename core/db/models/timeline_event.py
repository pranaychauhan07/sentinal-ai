"""`TimelineEvent` — blueprint §8's chronological record of what happened
during a case, distinct from the in-memory, per-run
`CaseInvestigationState.execution_history` (core/graph/state.py): this table
survives across investigation runs and is what a future Threat Timeline UI
(blueprint §13, Milestone M6) reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class TimelineEventType(StrEnum):
    """Closed set of pipeline stages this milestone's orchestration
    (`core/services/case_service.py`) actually produces. Additive — a future
    agent/milestone extends this enum rather than freeform strings
    (constitution §2, "Enums")."""

    CASE_OPENED = "case_opened"
    EVIDENCE_INGESTED = "evidence_ingested"
    IOC_EXTRACTED = "ioc_extracted"
    FINDING_GENERATED = "finding_generated"
    AGENT_ANALYSIS = "agent_analysis"
    CASE_STATUS_CHANGED = "case_status_changed"
    MANUAL_NOTE = "manual_note"


class TimelineEvent(Entity):
    __tablename__ = "timeline_events"
    __table_args__ = (
        Index("ix_timeline_events_case_id", "case_id"),
        Index("ix_timeline_events_timestamp", "timestamp"),
        Index("ix_timeline_events_source_finding_id", "source_finding_id"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(nullable=False)
    event_type: Mapped[TimelineEventType] = mapped_column(
        SqlEnum(
            TimelineEventType,
            name="timeline_event_type_enum",
            values_callable=lambda e: [x.value for x in e],
        ),
        nullable=False,
    )
    #: Nullable — not every timeline entry traces back to a specific
    #: Finding (e.g. `EVIDENCE_INGESTED` doesn't yet have one).
    source_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    narrative: Mapped[str] = mapped_column(Text, nullable=False)
