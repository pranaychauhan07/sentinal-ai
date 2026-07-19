"""`MitreTechnique` — reference table seeded from the vendored MITRE ATT&CK
STIX bundle, mirroring `core/db/models/mitre_tactic.py`'s versioning
precedent exactly. `tactic_shortnames_json`/`platforms_json` store their
respective lists as JSON text (constitution §7 precedent: `IOC.metadata_json`/
`Evidence.parsed_json` already store structured Pydantic content as a JSON
string column rather than a separate array type, for portability across the
SQLite/Postgres dialects this project supports — see docs/adr/0004).
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class MitreTechnique(Entity):
    __tablename__ = "mitre_techniques"
    __table_args__ = (
        UniqueConstraint(
            "technique_id", "attack_spec_version", name="uq_mitre_techniques_id_version"
        ),
        Index("ix_mitre_techniques_technique_id", "technique_id"),
        Index("ix_mitre_techniques_attack_spec_version", "attack_spec_version"),
    )

    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tactic_shortnames_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    platforms_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
