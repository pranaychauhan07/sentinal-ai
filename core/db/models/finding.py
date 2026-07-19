"""`Finding` — the Finding & MITRE ATT&CK Intelligence Engine's persistence
table (docs/adr/0013-finding-mitre-intelligence-engine-shape.md point 6),
the third real domain table after `Evidence` (ADR-0011) and `IOC`
(ADR-0012).

`case_id` **is now a real foreign key** to `cases.id` — the FK-tightening
migration (`7ae8f470d5e7`) applied it once Milestone M1's `Case` model
existed, following the exact precedent `Evidence.case_id`/`IOC.case_id` set.
`primary_evidence_id`/`primary_ioc_id` are also real, nullable foreign keys
(`evidence`/`iocs` already exist) — they identify the Finding's
first/primary supporting reference for indexed lookups; the complete
`evidence_refs`/`ioc_refs` list lives in `finding_data_json` (the serialized
`core.findings.models.FindingRecord`), matching the `IOC.metadata_json`/
`Evidence.parsed_json` "ORM row is persistence, Pydantic model is the full
contract" pattern.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.findings.models import FindingPriority, FindingSeverity, FindingStatus


class Finding(Entity):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_case_id", "case_id"),
        Index("ix_findings_primary_evidence_id", "primary_evidence_id"),
        Index("ix_findings_primary_ioc_id", "primary_ioc_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_priority", "priority"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    primary_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    primary_ioc_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("iocs.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[FindingSeverity] = mapped_column(
        SqlEnum(
            FindingSeverity,
            name="finding_severity_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    status: Mapped[FindingStatus] = mapped_column(
        SqlEnum(
            FindingStatus,
            name="finding_status_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=FindingStatus.OPEN,
    )
    priority: Mapped[FindingPriority] = mapped_column(
        SqlEnum(
            FindingPriority,
            name="finding_priority_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
    )
    risk_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    ioc_count: Mapped[int] = mapped_column(nullable=False, default=0)
    finding_data_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
