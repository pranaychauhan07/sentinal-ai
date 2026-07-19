# ADR-0012: Threat Intelligence & IOC Extraction Framework Shape

**Status:** Accepted
**Date:** 2026-07-19

## Purpose

The task requested this session is a complete, reusable Threat Intelligence &
IOC Extraction Framework: extraction, validation, normalization,
deduplication, a detection rule engine, threat scoring, classification,
confidence calculation, evidence attribution, and unimplemented provider
interfaces — explicitly excluding MITRE mapping, incident correlation, and
LLM reasoning. `context/01_blueprint.md` §7/§12 assigns IOC extraction to the
Threat Hunting Agent, calling `core/tools/log_tools.py` and
`core/tools/mitre_tools.py` as plain functions. The requested scope is far
larger than a tool file — twelve components, twenty IOC types, a nine-stage
pipeline — and has no assigned home in the blueprint's folder structure
(`context/01_blueprint.md` §6).

This mirrors the exact precedent ADR-0009 (Multi-Agent Framework), ADR-0010
(Memory & Knowledge Layer), and ADR-0011 (Evidence Ingestion & Parser
Framework) set: build the reusable, deterministic-first infrastructure ahead
of the concrete agent that will eventually sit on top of it, as a new
top-level `core/` package, documented via ADR before implementation. This ADR
records that extension.

## Decisions

1. **`core/threat_intel/` is a new leaf package, peer to `core/parsers` and
   `core/tools`.** It sits at the same tier in `docs/dependency-rules.md`'s
   layer stack ("deterministic functions") as `core/tools`/`core/parsers` —
   IOC extraction from `NormalizedEvidence` is exactly the kind of
   deterministic, checkable computation constitution §1.9 requires to be a
   plain function, not LLM reasoning. It may import `core.parsers.models`
   (only the `NormalizedEvidence`/`EvidenceRecord` input contract) and
   `core.config`/`core.logging`/`core.exceptions`; it may **not** import
   `core.agents`, `core.graph`, `core.memory`, or `core.db` — identical
   boundary to `core/parsers` itself. Importing another leaf's *models* is
   not a new pattern: `core/db/models/evidence.py` already imports
   `core.parsers.models.EvidenceType` today. `docs/dependency-rules.md`'s
   rule 5 is extended (not replaced) to name `core/threat_intel` alongside
   `core/tools`/`core/parsers`.

2. **`core/services/threat_intel_service.py` may import `core/threat_intel`,
   `core/parsers` (for the `NormalizedEvidence` pipeline input type), and
   `core/memory` (the same advisory `notify_memory` pattern
   `evidence_service.py` established) directly** — a new rule "4b" in
   `docs/dependency-rules.md`, scoped exactly to this module the same way
   rule 4a is scoped exactly to `evidence_service.py`. IOC extraction is
   deterministic, pre-investigation processing (blueprint §9 happens before
   the Coordinator/graph runs); a future `core/agents/threat_hunter_agent.py`
   calls this service's pipeline the same way a future `parser_agent.py`
   would call `ingest_evidence()`.

3. **`IOC.evidence_id` is a real foreign key to `evidence.id`; `IOC.case_id`
   is a plain UUID column, not a foreign key.** Unlike ADR-0011's
   `Evidence.case_id` (where nothing to reference existed yet), the
   `evidence` table already exists (ADR-0011) — an IOC always originates
   from a specific parsed artifact, so the FK is real from the start.
   `case_id` still has no `Case` table to reference; it follows the same
   precedent `Evidence.case_id` set, resolved by the same follow-up
   migration Milestone M1 already owes `Evidence.case_id`.

4. **Threat Intelligence Provider interfaces (MISP, AlienVault OTX,
   VirusTotal, AbuseIPDB, GreyNoise, OpenCTI) are `typing.Protocol`
   definitions only, in `core/threat_intel/interfaces.py`, with an empty
   `ProviderRegistry` (`core/threat_intel/provider_registry.py`)** — mirrors
   `core/knowledge/interfaces.py`'s "structural contract, zero
   implementation" pattern (ADR-0010) exactly. No network call, no API
   client, no credential handling beyond the `Settings` fields themselves
   exists in this session's code, per explicit task instruction.

## Refinements (requested during planning, before implementation)

- **Nine explicit pipeline stages** on `IOCExtractionPipeline`
  (`core/services/threat_intel_service.py`), matching the task's own
  diagram: `discover` (Evidence → IOC Discovery) → `validate` → `normalize`
  → `deduplicate` → `classify` (Detection Rule Engine) → `score` (Threat
  Scoring Engine + Confidence Calculator) → `persist` → `publish_event` →
  `notify_memory`. Each stage is a small, independently unit-testable
  method, identical shape to `EvidencePipeline`.
- **One data-driven `IOCExtractionEngine` (`core/threat_intel/extractor.py`),
  not twenty near-duplicate per-type extractor classes.** All twenty IOC
  patterns (`core/threat_intel/patterns.py`) and per-type normalizers
  (`core/threat_intel/normalizer.py`) are dispatched from one table-driven
  engine — constitution §1.9 ("never duplicated across files") and the
  task's own "no duplicated logic" requirement. Extensibility for new IOC
  types is still provided by `ExtractorRegistry`
  (`core/threat_intel/registry.py`), plugin-capable via
  `importlib.metadata.entry_points(group="cdc.threat_intel_extractors")`,
  mirroring `ParserRegistry` exactly.
- **Regex safety is a first-class, testable concern.**
  `core/threat_intel/patterns.py`'s twenty patterns are all bounded
  (anchored character classes, explicit `{m,n}` quantifiers, no nested
  quantifiers), and `core/threat_intel/rules.py`'s `REGEX`-type detection
  rules are validated at registration time
  (`validate_regex_safety` in `core/threat_intel/exceptions.py`'s sibling
  `validation.py`) against a catastrophic-backtracking heuristic (rejecting
  nested/overlapping quantifiers) and always evaluated against a
  length-capped input (`Settings.threat_intel_max_regex_input_chars`) —
  never against unbounded evidence text.
- **Detection rules carry Sigma-adjacent metadata from the start**
  (`rule_id`, `title`≈`name`, `level`≈severity via `ThreatSeverity`,
  `status`≈`enabled`, `tags`) without depending on a Sigma library or
  importing real Sigma rules — "Future Sigma rule compatibility" per the
  task, deferred exactly as far as `docs/roadmap.md`'s existing "Sigma rule
  engine" future-expansion entry (blueprint §17) already deferred it.

## Scope Cuts (explicit, not silent)

- No MITRE ATT&CK mapping — `core/threat_intel/classification.py`'s
  `IOCClassification.category` is a plain string category
  (`malicious`/`suspicious`/`benign`/`unknown`), never a MITRE technique ID.
  `core/threat_intel/interfaces.py` has no MITRE-shaped Protocol.
- No incident/cross-case correlation — `core/threat_intel/dedup.py`
  deduplicates *within* one extraction run's candidate IOC set; it never
  queries other cases' persisted IOCs. `IOCRepository.find_by_value_and_type`
  exists as a lookup primitive a future correlation feature could use, but
  nothing in this session's pipeline calls it for that purpose.
- No LLM reasoning anywhere in `core/threat_intel` or
  `threat_intel_service.py` — every stage is a deterministic function,
  matching constitution §1.9.
- No concrete `ThreatIntelProvider`/`IOCEnrichmentProvider` implementation
  (MISP/OTX/VirusTotal/AbuseIPDB/GreyNoise/OpenCTI) — interfaces and an
  empty registry only, per explicit instruction.
- No FastAPI route — mirrors ADR-0011's identical scope cut; wiring
  `extract_threat_intelligence()` to `apps/api` is natural follow-up once
  `Case` exists.

## Alternatives Considered

- **Fold IOC extraction into `core/tools/log_tools.py` as the blueprint
  originally sketched** — rejected; the task's scope (twelve components, a
  nine-stage pipeline, an independent DB table and service) is
  architecturally a peer of the Evidence Ingestion Framework, not a single
  tool function. Forcing it into one file would violate constitution §1.3
  ("small, focused modules") on day one.
- **Twenty separate `BaseIOCExtractor` subclasses, one per IOC type** —
  rejected as needless duplication; nineteen of the twenty are "run this
  regex, run this validator, run this normalizer" with no other divergent
  behavior. One data-driven engine plus a registry seam for a genuinely
  novel future extractor (e.g. an ML-based extractor) serves both goals.
- **Route IOC extraction through `core/graph`** — rejected for the same
  reason ADR-0011 rejected it for evidence ingestion: nothing here branches
  on investigation state; it is pre-investigation, deterministic processing.

## Consequences

- A future `core/agents/threat_hunter_agent.py` can be added without
  changing `core/threat_intel` or `threat_intel_service.py` — it calls
  `extract_threat_intelligence()` and reasons over the typed
  `ThreatIntelExtractionResult`, exactly as ADR-0011 predicted for
  `parser_agent.py`.
- `IOC.case_id`'s missing FK constraint joins `Evidence.case_id` as a known,
  tracked gap resolved by the same Milestone M1 follow-up migration.
- The `cdc.threat_intel_extractors` and `cdc.threat_intel_providers`
  entry-point groups are public extension contracts from this point forward.
- `docs/dependency-rules.md` gains one new leaf-tier package (rule 5) and one
  new services-layer exception (rule 4b), both scoped narrowly, in the same
  commit as this ADR.
