"""`MitreMitigation` — reference table seeded from the vendored MITRE
ATT&CK STIX bundle, mirroring `core/db/models/mitre_tactic.py`'s versioning
precedent."""

from __future__ import annotations

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class MitreMitigation(Entity):
    __tablename__ = "mitre_mitigations"
    __table_args__ = (
        UniqueConstraint(
            "mitigation_id", "attack_spec_version", name="uq_mitre_mitigations_id_version"
        ),
        Index("ix_mitre_mitigations_mitigation_id", "mitigation_id"),
        Index("ix_mitre_mitigations_attack_spec_version", "attack_spec_version"),
    )

    mitigation_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
