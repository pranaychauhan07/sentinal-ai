"""`Evidence` — the first real domain table (blueprint §8), scoped to just
this table per `docs/adr/0011-evidence-ingestion-pipeline-shape.md`: `Case`,
`Finding`, `MitreTechnique`, `TimelineEvent`, `Report` arrive with Milestone
M1 and each get their own sibling module in this package.

``case_id`` is a plain UUID column, **not yet a foreign key** — ``Case``
doesn't exist yet. This follows the exact precedent
``core/memory/db_models.py::MemoryRecordRow`` set for the same reason
(ADR-0010): a leaf-adjacent persistence layer must not block on a domain
model that hasn't been built. Once M1 adds ``Case``, a follow-up additive
migration adds the FK constraint (constitution §7, "Future scalability").
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import Index, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.parsers.models import EvidenceType


class EvidenceStatus(StrEnum):
    """Lifecycle state of one uploaded artifact — distinct from parser
    confidence (a `PARSED` row can still carry low confidence)."""

    UPLOADED = "uploaded"
    PARSED = "parsed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class Evidence(Entity):
    """One uploaded artifact and the result of running it through
    `core/services/evidence_service.py`'s ingestion pipeline.

    `parsed_json` stores the serialized `core.parsers.models.
    NormalizedEvidence` (constitution §7: ORM rows are the persistence
    representation; Pydantic models are what every other layer works with —
    translation happens only here and in `core/db/evidence_repository.py`).
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_case_id", "case_id"),
        Index("ix_evidence_evidence_type", "evidence_type"),
        Index("ix_evidence_sha256", "sha256"),
        Index("ix_evidence_status", "status"),
    )

    #: Plain UUID, not a ForeignKey — see module docstring.
    case_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        SqlEnum(
            EvidenceType,
            name="evidence_type_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    encoding: Mapped[str] = mapped_column(String(32), nullable=False)
    parser_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    parser_confidence: Mapped[float | None] = mapped_column(nullable=True)
    parsed_json: Mapped[str | None] = mapped_column(nullable=True)
    status: Mapped[EvidenceStatus] = mapped_column(
        SqlEnum(
            EvidenceStatus,
            name="evidence_status_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
        default=EvidenceStatus.UPLOADED,
    )
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(nullable=False)
    parsed_at: Mapped[datetime | None] = mapped_column(nullable=True)
