# core/knowledge/mitre — Concrete MITRE ATT&CK Knowledge Source

**Purpose:** Fulfills `core/knowledge`'s `KnowledgeSourceType.MITRE_ATTACK`
slot (ADR-0010's deliberately deferred promise). Parses the vendored,
offline STIX 2.1 bundle (`data/mitre/raw/`) into typed reference models and
exposes them both generically (`MitreAttackSource`, a
`core.knowledge.interfaces.KnowledgeSource`) and via fast, MITRE-specific
lookups (`MitreLookup`) that `core/findings/mapping_engine.py` calls
directly.

**Responsibility:** Read-only reference data plus the pure functions that
parse and look it up. Never mutated at runtime — a new ATT&CK release is a
new vendored file imported via `scripts/mitre/import_attack_bundle.py`, not
an in-place edit.

**Implemented (docs/adr/0013-finding-mitre-intelligence-engine-shape.md):**
- `models.py` — `MitreTactic`, `MitreTechnique`, `MitreSoftware`,
  `MitreGroup`, `MitreMitigation`, `MitreRelationship`, `MitreDataset`
  (the parsed container), all versioned via `attack_spec_version`.
- `exceptions.py` — `MalformedMitreDataError`, `UnknownTechniqueError`,
  `UnsupportedAttackVersionError`.
- `loader.py` — `load_bundle`/`load_bundle_from_path`: the one STIX-parsing
  implementation, reused by both the in-memory source and the DB seed
  script. Reads local files only — no network call, ever.
- `source.py` — `MitreAttackSource`, a concrete `KnowledgeSource`.
- `lookup.py` — `MitreLookup`: `technique_by_id`, `tactics_for_technique`,
  `mitigations_for_technique`, `groups_using_technique`,
  `software_using_technique`.
- `bootstrap.py` — `load_mitre_dataset(settings)`: turns
  `Settings.mitre_attack_data_path`/`mitre_attack_version` into a validated
  `MitreDataset`. Not a global singleton — callers construct and pass this
  explicitly (constitution §2).

**Why this lives under `core/knowledge`, not a new package:** MITRE ATT&CK
reference data is exactly the "static reference data" the Knowledge Layer
(`context/01_blueprint.md` §4) was always meant to hold; a second, competing
MITRE model layer elsewhere would violate constitution §1.6 ("one clear
home"). The *mapping engine* that consumes this data (rule-based
IOC-to-technique mapping, confidence, Finding generation) lives in the peer
leaf package `core/findings/`, which imports this package read-only.

**Not built here:** any mapping logic, any `Finding` concept, any DB
persistence (see `core/db/models/mitre_technique.py` etc. and
`core/findings/README.md`) — this package is data and lookups only.
