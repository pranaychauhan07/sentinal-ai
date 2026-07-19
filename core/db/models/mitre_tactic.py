"""`MitreTactic` — reference table seeded from the vendored MITRE ATT&CK
STIX bundle (`data/mitre/raw/`) via `scripts/mitre/import_attack_bundle.py`,
never written by application logic
(docs/adr/0013-finding-mitre-intelligence-engine-shape.md point 5).

`tactic_id` (e.g. `TA0006`) is a **unique indexed business column, not the
primary key** — constitution §7's explicit rule: MITRE IDs look permanently
stable but are still a business identifier, not a surrogate key.
`attack_spec_version` makes a future ATT&CK release additive new rows,
never an in-place mutation of an existing tactic.
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity


class MitreTactic(Entity):
    __tablename__ = "mitre_tactics"
    __table_args__ = (
        UniqueConstraint("tactic_id", "attack_spec_version", name="uq_mitre_tactics_id_version"),
        Index("ix_mitre_tactics_tactic_id", "tactic_id"),
        Index("ix_mitre_tactics_attack_spec_version", "attack_spec_version"),
    )

    tactic_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    shortname: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
