"""`FindingMitreMapping` — the real many-to-many join table between
`Finding` and `MitreTechnique` (docs/adr/0013 point 6): one Finding can map
to several techniques, and one technique is shared across many Findings,
which a single FK column on `Finding` cannot represent.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class FindingMitreMapping(Entity):
    __tablename__ = "finding_mitre_mappings"
    __table_args__ = (
        UniqueConstraint("finding_id", "mitre_technique_id", name="uq_finding_mitre_mapping_pair"),
        Index("ix_finding_mitre_mappings_finding_id", "finding_id"),
        Index("ix_finding_mitre_mappings_mitre_technique_id", "mitre_technique_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    mitre_technique_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("mitre_techniques.id", ondelete="RESTRICT"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    mapping_source: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
