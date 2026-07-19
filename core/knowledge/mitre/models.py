"""Typed MITRE ATT&CK reference models — the Knowledge Layer's concrete
MITRE dataset shapes, fulfilling `core.knowledge`'s `KnowledgeSourceType.
MITRE_ATTACK` slot that ADR-0010 deliberately left unimplemented
(docs/adr/0013-finding-mitre-intelligence-engine-shape.md point 1).

Every model carries `attack_spec_version` so a future ATT&CK release is a
new set of rows, never an in-place mutation of an existing technique/tactic/
software/group/mitigation (constitution §7, append-only versioning).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MitreObjectType(StrEnum):
    """The closed set of STIX object types `loader.py` understands. Not
    every STIX 2.1 object type — only the ones ATT&CK's Enterprise matrix
    uses and this engine maps against."""

    TACTIC = "x-mitre-tactic"
    TECHNIQUE = "attack-pattern"
    SOFTWARE_TOOL = "tool"
    SOFTWARE_MALWARE = "malware"
    GROUP = "intrusion-set"
    MITIGATION = "course-of-action"
    RELATIONSHIP = "relationship"


class MitreRelationshipType(StrEnum):
    """The closed set of ATT&CK relationship semantics this engine
    understands. STIX supports more `relationship_type` values than this;
    unrecognized ones are skipped by the loader, not raised as errors
    (constitution §1.7 — a bundle with unrelated relationship types must
    degrade gracefully, not crash import)."""

    USES = "uses"
    MITIGATES = "mitigates"


class MitreTactic(BaseModel):
    """One ATT&CK tactic (e.g. TA0006 Credential Access)."""

    model_config = ConfigDict(frozen=True)

    tactic_id: str
    name: str
    shortname: str
    description: str
    attack_spec_version: str


class MitreTechnique(BaseModel):
    """One ATT&CK technique (e.g. T1110 Brute Force). `tactic_shortnames`
    holds every tactic phase this technique belongs to — several ATT&CK
    techniques (e.g. T1078 Valid Accounts) span more than one tactic."""

    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str
    description: str
    tactic_shortnames: tuple[str, ...]
    platforms: tuple[str, ...] = ()
    attack_spec_version: str


class MitreSoftware(BaseModel):
    """One ATT&CK software entry (a `tool` or `malware` STIX object, e.g.
    S0002 Mimikatz)."""

    model_config = ConfigDict(frozen=True)

    software_id: str
    name: str
    description: str
    is_malware: bool
    attack_spec_version: str


class MitreGroup(BaseModel):
    """One ATT&CK threat group (an `intrusion-set` STIX object, e.g. G0007
    APT28)."""

    model_config = ConfigDict(frozen=True)

    group_id: str
    name: str
    description: str
    attack_spec_version: str


class MitreMitigation(BaseModel):
    """One ATT&CK mitigation (a `course-of-action` STIX object, e.g. M1032
    Multi-factor Authentication)."""

    model_config = ConfigDict(frozen=True)

    mitigation_id: str
    name: str
    description: str
    attack_spec_version: str


class MitreRelationship(BaseModel):
    """One `uses`/`mitigates` edge between two ATT&CK objects, referenced by
    their business IDs (e.g. `G0007` -> `T1566`), not raw STIX UUIDs — every
    other model/lookup in this engine keys on business IDs, so relationships
    do too, matching constitution §7's "never a natural key as PK, but a
    stable business identifier is still how domain code refers to a row"
    spirit applied to an edge instead of a row."""

    model_config = ConfigDict(frozen=True)

    relationship_type: MitreRelationshipType
    source_id: str
    target_id: str
    description: str = ""
    attack_spec_version: str


class MitreDataset(BaseModel):
    """One fully-parsed ATT&CK bundle — everything
    `core.knowledge.mitre.loader.load_bundle` produces, and the one
    container `MitreAttackSource`/`MitreLookup`/the DB seed script all
    consume, so there is exactly one place STIX parsing happens
    (constitution §1.9, "never duplicated across files")."""

    model_config = ConfigDict(frozen=True)

    attack_spec_version: str
    tactics: tuple[MitreTactic, ...] = Field(default_factory=tuple)
    techniques: tuple[MitreTechnique, ...] = Field(default_factory=tuple)
    software: tuple[MitreSoftware, ...] = Field(default_factory=tuple)
    groups: tuple[MitreGroup, ...] = Field(default_factory=tuple)
    mitigations: tuple[MitreMitigation, ...] = Field(default_factory=tuple)
    relationships: tuple[MitreRelationship, ...] = Field(default_factory=tuple)
