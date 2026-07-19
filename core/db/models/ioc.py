"""`IOC` — the Threat Intelligence Layer's persistence table
(docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md point
3), the second real domain table after `Evidence` (ADR-0011).

``evidence_id`` is a real foreign key to ``evidence.id``. ``case_id`` **is
now also a real foreign key** to ``cases.id`` — the FK-tightening migration
(``7ae8f470d5e7``) applied it once Milestone M1's `Case` model existed,
following the exact precedent ``Evidence.case_id`` set (ADR-0011).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.threat_intel.models import IOCType, ThreatCategory, ThreatSeverity


class IOCStatus(StrEnum):
    """Lifecycle state of one persisted IOC — distinct from
    `ThreatCategory` (a `DISMISSED` row can still carry a `MALICIOUS`
    classification; status is analyst/pipeline workflow state, not threat
    assessment)."""

    ACTIVE = "active"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"
    FAILED = "failed"


class IOC(Entity):
    """One persisted, scored, classified indicator of compromise — the
    result of running one `core.parsers.models.NormalizedEvidence` through
    `core/services/threat_intel_service.py`'s extraction pipeline.

    `metadata_json` stores the serialized `core.threat_intel.models.
    ScoredIOC` (constitution §7: ORM rows are the persistence
    representation; Pydantic models are what every other layer works with).
    """

    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_case_id", "case_id"),
        Index("ix_iocs_evidence_id", "evidence_id"),
        Index("ix_iocs_ioc_type", "ioc_type"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_severity", "severity"),
        Index("ix_iocs_classification", "classification"),
        Index("ix_iocs_status", "status"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True
    )
    ioc_type: Mapped[IOCType] = mapped_column(
        SqlEnum(
            IOCType, name="ioc_type_enum", values_callable=lambda enum: [e.value for e in enum]
        ),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    raw_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    severity: Mapped[ThreatSeverity] = mapped_column(
        SqlEnum(
            ThreatSeverity,
            name="threat_severity_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=ThreatSeverity.INFO,
    )
    classification: Mapped[ThreatCategory] = mapped_column(
        SqlEnum(
            ThreatCategory,
            name="threat_category_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=ThreatCategory.UNKNOWN,
    )
    composite_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    rule_match_count: Mapped[int] = mapped_column(nullable=False, default=0)
    occurrence_count: Mapped[int] = mapped_column(nullable=False, default=1)
    extractor_name: Mapped[str] = mapped_column(String(64), nullable=False)
    extractor_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[IOCStatus] = mapped_column(
        SqlEnum(
            IOCStatus, name="ioc_status_enum", values_callable=lambda enum: [e.value for e in enum]
        ),
        nullable=False,
        default=IOCStatus.ACTIVE,
    )
    metadata_json: Mapped[str | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(nullable=False)
