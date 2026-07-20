# ADR-0022: MITRE Mapping Agent

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Build blueprint §7's **MITRE Mapping Agent** — the one remaining M2 gap.
Blueprint's exact scope: *"Cross-cutting technique mapper used by SOC/
Threat Hunting/Incident agents. Responsibilities: map a described behavior
... to MITRE technique ID ..., with tactic/phase. Input: natural-language
behavior description or structured finding. Output: `MitreMapping[]`
(technique ID, name, tactic, confidence). Tools used: `mitre_tools.py`
against `knowledge/mitre_attack.json`. Failure handling: returns 'unmapped'
rather than forcing a low-confidence guess into the report."*

## The conflict this ADR resolves

The task that requested this agent asked for a full, new "MITRE Mapping
framework": an ATT&CK Mapping Engine, a Technique Matching Engine, a
Confidence Calculator, Mapping Metrics, Audit Events, evidence aggregation,
deduplication, and persistence — as if none of this existed. Before writing
any code, a review of the existing codebase found that **almost all of it
already exists**, built under ADR-0013 (the Finding & MITRE ATT&CK
Intelligence Engine) and already wired into production:

- `core/findings/mapping_engine.py` (`MitreMappingEngine`) — rule-based
  technique matching + confidence, already run for every case.
- `core/findings/confidence_engine.py` (`ConfidenceEngine`) — the seven-
  dimension weighted confidence calculator.
- `core/findings/evidence_aggregation.py`, `dedup.py`, `severity.py`,
  `finding_generator.py` — evidence aggregation, deduplication, severity/
  priority assignment.
- `core/findings/metrics.py`, `events.py`, `audit.py` — mapping metrics and
  audit events (`TechniqueMapped`, `ConfidenceUpdated`, ...).
- `core/knowledge/mitre/lookup.py` (`MitreLookup`) — already implements
  `tactics_for_technique`, `groups_using_technique`,
  `software_using_technique`, `mitigations_for_technique`.
- `core/services/finding_service.py`
  (`generate_findings_for_case`/`FindingGenerationPipeline`) — a full
  six-stage pipeline (discover -> map_and_generate -> deduplicate ->
  persist -> publish_event -> notify_memory), already called from
  `core/services/case_service.py` on every evidence upload, with real DB
  persistence (`Finding`, `FindingMitreMapping` tables).

Building a second, parallel implementation of any of this would violate
constitution §1.6 ("one clear home"), §1.10 ("the architecture is not
renegotiated per feature"), and §14.9 ("never duplicate functionality").
This conflict was surfaced to the user before any code was written, who
chose the **thin agent + tool** scope: extend the existing engine's output
additively (Group/Software resolution) and add only the two pieces the
blueprint names that do not yet exist — `core/tools/mitre_tools.py` and
`core/agents/mitre_mapping_agent.py` — rather than rebuilding the engine.

## What this ADR actually adds

1. **`core/tools/mitre_tools.py`** (new) — `MitreMappingResolutionTool`.
   Never re-derives a technique-to-Finding mapping or its confidence
   (that stays `MitreMappingEngine`'s job). It only *resolves* reference
   metadata for already-mapped technique IDs via `MitreLookup`: tactic
   phases, sub-technique parent IDs (ATT&CK's own `"T1110.001"` dot
   convention — no separate parent/child data is vendored or needed),
   associated threat groups, associated software, and mitigations. This is
   the task's named "Technique Matching Engine" (aggregation across
   matches for one technique), "Tactic Resolver", "Sub-technique
   Resolver", "Group Mapper", "Software Mapper", and "Mitigation Mapper" —
   implemented as one cohesive resolution tool wrapping `MitreLookup`'s
   already-existing methods, not six separate duplicate engines.

   Unlike every other `core/tools/*.py` module, this tool's input stays
   typed (not dict-shaped) and its constructor takes an injected
   `MitreLookup`: `core/tools` is explicitly allowed to import
   `core/knowledge` directly (docs/dependency-rules.md rule 5) —
   `core.knowledge.mitre` is shared reference data, not a sibling leaf's
   private model.

2. **`core/agents/mitre_mapping_agent.py`** (new) — `MitreMappingAgent`,
   the eighth concrete specialist agent. Reads
   `CaseInvestigationState.mitre_mapping_records` (hydrated by
   `case_service.py` from the case's already-persisted
   `Finding.mitre_mappings`) and calls `MitreMappingResolutionTool` to
   produce a case-level `MitreCaseMappingSummary`. Never computes a
   mapping or confidence itself. Returns a `DEGRADED`, zero-technique
   "unmapped" result — never a forced low-confidence guess — when no
   mapping is present yet, exactly matching blueprint §7's documented
   failure handling.

   Unlike every other specialist agent in this codebase, this agent is
   explicitly permitted to import `core.knowledge.mitre` directly
   (docs/dependency-rules.md rule 4/4c: "core/agents may import ...
   core/knowledge ... Finding/MITRE mapping only") — MITRE reference data
   is shared knowledge-layer data this agent exists specifically to
   resolve against, not a sibling leaf's private model like
   `core.vulnerabilities`/`core.linux_security`/etc. are for every other
   specialist.

3. **Group/Software mapping additively surfaced** — `MitreLookup.
   groups_using_technique`/`software_using_technique` already existed but
   were unused by anything. This ADR is the first caller.

4. **Cross-cutting routing, not evidence-type-gated** — unlike every other
   specialist agent, `MitreMappingAgent`'s capability
   (`mitre_technique_mapping`) is appended to *every* evidence type's
   required-capability list in `case_service._required_capabilities_for`,
   since Finding generation (and therefore MITRE mapping) already runs
   unconditionally on every evidence upload, regardless of which
   specialist(s) that evidence type also routes to.

5. **`_hydrate_mitre_mapping_records`** (new, `case_service.py`) — reduces
   the case's persisted `Finding.finding_data_json` (each already a
   serialized `core.findings.models.FindingRecord`) to plain dicts via
   `json.loads`, never importing `core.findings.models.FindingRecord`
   directly (that import edge belongs to `finding_service.py` specifically
   per rule 4c) and never re-mapping or re-scoring anything. Scoped to the
   whole case (every Finding, not just the current upload's), matching
   blueprint §13's MITRE ATT&CK matrix heatmap, which is inherently
   case-wide.

## What this ADR explicitly does not build

- A second mapping engine, confidence calculator, metrics collector, audit
  module, evidence aggregator, or deduplication engine — all already exist
  in `core/findings/` and are reused as-is.
- Any persistence beyond what `core/findings`/`finding_service.py` already
  do — this agent reads already-persisted data; it writes nothing new to
  the database.
- Incident response, report generation, or LLM reasoning of any kind.
- A redesign of `core/findings/`, `core/knowledge/mitre/`, or any prior
  agent/framework — only extended, per the user's explicitly chosen scope.

## Consequences

- `build_investigation_graph()` and `core/services/case_service.
  _run_specialist_agents` both gained a `settings: Settings` parameter
  (additive; `build_investigation_graph`'s defaults to `Settings()` when
  omitted) — `MitreMappingAgent`'s tool registry needs a loaded
  `MitreLookup`, built from `settings.mitre_attack_data_path`/
  `mitre_attack_version`, unlike every sibling specialist agent's
  no-argument tool-registry factory.
- `CaseInvestigationState` gained `mitre_mapping_records: list[Any]`
  (uniform with every other `*_records` field — `core/graph` has no
  documented import edge onto `core/findings`/`core/knowledge`, so the
  field stays generic even though the agent itself may import those
  packages typed).
- `CaseInvestigationResult`/`EvidenceUploadResponse` gained
  `mitre_technique_count`/`mitre_distinct_group_count` (additive, per
  constitution §13's versioning rule).
- Building a second `MitreLookup` per case-investigation run (one inside
  `finding_service.FindingGenerationPipeline`, one inside this agent's
  tool registry) is a known, accepted minor inefficiency — both load the
  same small, local, vendored JSON file, deterministically and offline.
  Not optimized in this ADR (no shared-instance seam exists between
  `core/services/finding_service.py` and `core/agents/
  mitre_mapping_agent.py` without a new, currently-unjustified coupling);
  flagged for a future session if profiling ever shows it matters.
- `docs/roadmap.md`'s M2 milestone is now fully closed.
