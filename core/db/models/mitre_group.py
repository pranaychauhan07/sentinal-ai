"""`MitreGroup` — reference table seeded from the vendored MITRE ATT&CK
STIX bundle, mirroring `core/db/models/mitre_tactic.py`'s versioning
precedent."""

from __future__ import annotations

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class MitreGroup(Entity):
    __tablename__ = "mitre_groups"
    __table_args__ = (
        UniqueConstraint("group_id", "attack_spec_version", name="uq_mitre_groups_id_version"),
        Index("ix_mitre_groups_group_id", "group_id"),
        Index("ix_mitre_groups_attack_spec_version", "attack_spec_version"),
    )

    group_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
