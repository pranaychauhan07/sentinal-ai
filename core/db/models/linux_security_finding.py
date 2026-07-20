"""`LinuxSecurityFinding` — the Linux Security Analysis Framework's
persistence table (docs/adr/0018-linux-security-threat-hunting-framework.md),
mirroring `core/db/models/vulnerability.py`'s shape exactly. Both `case_id`
and `evidence_id` are real foreign keys from the start (`Case`/`Evidence`
both already exist by the time this table was introduced, so no follow-up
migration is needed, matching `Vulnerability`'s identical precedent).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.linux_security.models import LinuxSecurityFindingCategory, LinuxSecuritySeverity


class LinuxSecurityFindingStatus(StrEnum):
    """Lifecycle state of one persisted finding — distinct from
    `LinuxSecuritySeverity` (a `DISMISSED` row can still carry a `CRITICAL`
    severity), mirroring `core.db.models.vulnerability.VulnerabilityStatus`'s
    identical shape."""

    ACTIVE = "active"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"
    FAILED = "failed"


class LinuxSecurityFindingRow(Entity):
    """One persisted, scored `core.linux_security.models.
    LinuxSecurityFinding` — the result of running one
    `core.parsers.models.NormalizedEvidence` (SSH auth / syslog) through
    `core/services/linux_security_service.py`'s analysis pipeline.

    Named `LinuxSecurityFindingRow` (not `LinuxSecurityFinding`) to avoid a
    same-name collision with the Pydantic model this ORM row persists —
    `metadata_json` stores the serialized `ScoredLinuxSecurityCandidate`
    group (constitution §7: ORM rows are the persistence representation;
    Pydantic models are what every other layer works with).
    """

    __tablename__ = "linux_security_findings"
    __table_args__ = (
        Index("ix_linux_security_findings_case_id", "case_id"),
        Index("ix_linux_security_findings_evidence_id", "evidence_id"),
        Index("ix_linux_security_findings_category", "category"),
        Index("ix_linux_security_findings_severity", "severity"),
        Index("ix_linux_security_findings_status", "status"),
        Index("ix_linux_security_findings_subject", "subject"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True
    )
    category: Mapped[LinuxSecurityFindingCategory] = mapped_column(
        SqlEnum(
            LinuxSecurityFindingCategory,
            name="linux_security_finding_category_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
    )
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="host")
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    description: Mapped[str] = mapped_column(nullable=False, default="")
    severity: Mapped[LinuxSecuritySeverity] = mapped_column(
        SqlEnum(
            LinuxSecuritySeverity,
            name="linux_security_severity_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=LinuxSecuritySeverity.INFO,
    )
    composite_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    occurrence_count: Mapped[int] = mapped_column(nullable=False, default=1)
    line_numbers_json: Mapped[str | None] = mapped_column(nullable=True)
    extractor_name: Mapped[str] = mapped_column(String(64), nullable=False)
    extractor_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[LinuxSecurityFindingStatus] = mapped_column(
        SqlEnum(
            LinuxSecurityFindingStatus,
            name="linux_security_finding_status_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=LinuxSecurityFindingStatus.ACTIVE,
    )
    metadata_json: Mapped[str | None] = mapped_column(nullable=True)
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(nullable=False)
