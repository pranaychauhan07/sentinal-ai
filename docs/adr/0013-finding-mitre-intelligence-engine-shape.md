# ADR-0013: Finding & MITRE ATT&CK Intelligence Engine Shape

**Status:** Accepted
**Date:** 2026-07-19

## Purpose

The task requested this session is a complete, deterministic Finding & MITRE
ATT&CK Intelligence Engine: map `core.threat_intel.models.ScoredIOC`s to
ATT&CK techniques/tactics with confidence, aggregate evidence, generate typed
`Finding`s, deduplicate/merge them, assign severity, persist them, and
publish lifecycle events — explicitly excluding LLM reasoning, investigation
logic, and cross-case incident correlation. `context/01_blueprint.md` §7/§8
assigns MITRE mapping to a thin cross-cutting "MITRE Mapping Agent" backed by
`core/tools/mitre_tools.py` against `core/knowledge/mitre_attack.json`, and
assigns `Finding`/`MitreTechnique` a small flat schema in §8's DB design. The
requested scope — a full five-table ATT&CK reference schema (Technique,
Tactic, Software, Group, Mitigation), a rule-based mapping engine with
configurable confidence, evidence aggregation with chain-of-custody,
multi-dimensional deduplication, and a typed `Finding` lifecycle with six
event types — is materially larger than either of those sketches and has no
single assigned home in the blueprint's folder structure.

This mirrors the exact precedent ADR-0009/0010/0011/0012 already set: build
the reusable, deterministic-first infrastructure ahead of the concrete agent
that will eventually consume it (the future `MitreMappingAgent`/
`ThreatHuntingAgent`/`IncidentResponseAgent`), as new `core/` packages,
documented via ADR before implementation. This ADR records that extension,
plus the resolution of four points raised during planning review.

## Decisions

1. **The MITRE reference data/model layer lives in `core/knowledge/mitre/`,
   not in a new package.** `core/knowledge` already reserves
   `KnowledgeSourceType.MITRE_ATTACK` and an empty `KnowledgeSourceRegistry`
   for exactly this (ADR-0010's explicitly deferred promise) — building a
   second, competing MITRE model layer elsewhere would duplicate an
   already-designated home (constitution §1.6). `core/knowledge/mitre/`
   adds: `models.py` (`MitreTechnique`, `MitreTactic`, `MitreSoftware`,
   `MitreGroup`, `MitreMitigation`, `MitreRelationship`, all versioned via
   `attack_spec_version`), `loader.py` (parses a vendored STIX 2.1 bundle
   into these models), `source.py` (`MitreAttackSource`, a concrete
   `KnowledgeSource` implementation registered under
   `KnowledgeSourceType.MITRE_ATTACK`), and `lookup.py` (fast in-memory
   technique/tactic/software/group/mitigation lookups the mapping engine
   needs beyond generic `KnowledgeSource.search`).

2. **`core/findings/` is a new leaf package, peer to `core/threat_intel` and
   `core/parsers`.** It owns the mapping engine, `Finding` model, evidence
   aggregation, confidence engine, severity assignment, and deduplication —
   everything the task's own diagram places between "MITRE Mapping" and
   "Persistence." It may import `core.knowledge` (already permitted by rule
   5) and, as a new documented sideways leaf-model import identical in
   shape to `core/threat_intel`'s import of `core.parsers.models`, it may
   import `core.threat_intel.models` (`ScoredIOC`, `IOCRecord`, `IOCType`,
   `ThreatSeverity` — its input contract only). It may **not** import
   `core.agents`, `core.graph`, `core.memory`, or `core.db`. `docs/
   dependency-rules.md` rule 5 is extended (not replaced) to name
   `core/findings` alongside `core/tools`/`core/parsers`/`core/threat_intel`,
   and to name this specific sideways import.

3. **`core/services/finding_service.py` may import `core/findings`,
   `core/threat_intel` (models only), `core/knowledge`, and `core/memory`
   directly** — a new rule "4c" in `docs/dependency-rules.md`, worded
   identically to 4a/4b and scoped exactly to this module. Finding
   generation, like evidence ingestion and IOC extraction, is deterministic,
   pre-investigation processing with no agent/LLM reasoning (constitution
   §1.9); a future `core/agents/threat_hunter_agent.py` or
   `mitre_mapping_agent.py` calls this service's pipeline the same way a
   future `parser_agent.py` calls `ingest_evidence()`.

4. **The official MITRE ATT&CK Enterprise STIX corpus is vendored locally,
   never fetched over the network at runtime**, per explicit instruction.
   Given the full corpus's size, this session vendors a curated,
   hand-authored subset in genuine STIX 2.1 bundle shape
   (`data/mitre/raw/attack-enterprise-15.1.json`) covering all 14 Enterprise
   tactics, 20 real, well-known techniques, 5 real software entries, 5 real
   groups, and 6 real mitigations, with real MITRE IDs and real
   `uses`/`mitigates` relationships. This is a representative curriculum
   subset for this milestone, not a byte-identical mirror of MITRE's
   published bundle download — documented honestly in
   `data/mitre/README.md`, never presented as the complete corpus.
   `scripts/mitre/import_attack_bundle.py` is the versioned import path: it
   accepts *any* STIX 2.1 bundle file (this curated one today, the complete
   official bundle or a future ATT&CG release tomorrow) plus a version
   string, and seeds the five reference tables — adding a new ATT&CK release
   is "vendor a new file, run the script with a new version," never an
   application-code change, satisfying the explicit requirement.

5. **`MitreTechnique.technique_id` (etc. for all five reference tables) is a
   unique indexed business column, never the primary key** — constitution
   §7's explicit rule, restated here because MITRE IDs look permanently
   stable and are a natural but forbidden PK choice. Every reference table
   has a surrogate UUID PK and an `attack_spec_version` column, so a future
   ATT&CK release is new rows (a new version), never an in-place mutation of
   existing ones — append-only versioning.

6. **`Finding.case_id` is a plain UUID column, not a foreign key** — `Case`
   still doesn't exist (Milestone M1's own domain model is still
   outstanding), following the exact `Evidence.case_id`/`IOC.case_id`
   precedent, resolved by the same owed follow-up migration.
   `Finding.evidence_id` and `Finding.ioc_id` **are** real, nullable foreign
   keys — `evidence`/`iocs` already exist. `finding_mitre_mappings` is a
   real many-to-many join table (`finding_id` FK, `mitre_technique_id` FK,
   plus `confidence`/`mapping_source`/`attack_spec_version`), because one
   `Finding` can map to several techniques and one technique is shared
   across many `Finding`s.

## Alternatives Considered

- **Build the MITRE model layer inside `core/findings/` instead of
  `core/knowledge/mitre/`** — rejected; `core/knowledge` already has the
  reserved `KnowledgeSourceType.MITRE_ATTACK` slot and the `KnowledgeSource`
  Protocol ADR-0010 built for exactly this. Splitting MITRE reference data
  across two packages would violate constitution §1.6 ("one clear home").
- **Fetch the real ATT&CK STIX bundle from GitHub at build/CI time** —
  rejected outright per explicit instruction: the application must work
  completely offline, with no runtime network fetch of MITRE data.
- **Hand-write only a handful of ad hoc technique dicts instead of a real
  STIX bundle** — rejected; a STIX-shaped file is what makes
  `scripts/mitre/import_attack_bundle.py` a genuine, reusable import path for
  the *complete* official bundle later, not a one-off migration script that
  would need rewriting when real data arrives.
- **Give `Finding` a single `mitre_technique_id` column instead of a join
  table** — rejected; the task explicitly requires one-finding-to-many-
  techniques and many-IOCs-to-one-technique mapping, which a single FK
  column cannot represent.

## Consequences

- A future `core/agents/mitre_mapping_agent.py` or extended
  `threat_hunter_agent.py` can be added without changing `core/findings`,
  `core/knowledge/mitre`, or `finding_service.py` — it calls
  `generate_findings_for_case()` and reasons over the typed
  `FindingGenerationResult`.
- `Finding.case_id`'s missing FK constraint joins `Evidence.case_id`/
  `IOC.case_id` as a known, tracked gap resolved by the same Milestone M1
  follow-up migration.
- `data/mitre/raw/attack-enterprise-15.1.json`'s curated-subset status is a
  documented, honest limitation: mapping confidence/coverage is bounded by
  which of the 20 techniques this session vendored, not by the mapping
  engine's design, which supports the full ATT&CK technique space
  unchanged once a complete bundle is imported via the same script.
- `docs/dependency-rules.md` gains one new leaf-tier package (rule 5,
  extended) and one new services-layer exception (rule 4c), both scoped
  narrowly, in the same commit as this ADR.
