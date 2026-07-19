"""`MitreSoftware` — reference table seeded from the vendored MITRE ATT&CK
STIX bundle, mirroring `core/db/models/mitre_tactic.py`'s versioning
precedent."""

from __future__ import annotations

from sqlalchemy import Boolean, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class MitreSoftware(Entity):
    __tablename__ = "mitre_software"
    __table_args__ = (
        UniqueConstraint("software_id", "attack_spec_version", name="uq_mitre_software_id_version"),
        Index("ix_mitre_software_software_id", "software_id"),
        Index("ix_mitre_software_attack_spec_version", "attack_spec_version"),
    )

    software_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_malware: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
