# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Still no concrete specialist agent, `Case` model, or investigation logic exists.** What is now complete, beyond the M0 engineering foundation, the M3 Multi-Agent Framework, the M6 Memory & Knowledge Layer, the M1 Evidence Ingestion & Parser Framework, and the M4 Threat Intelligence & IOC Extraction Framework, is the **Finding & MITRE ATT&CK Intelligence Engine**: a reusable, agent-independent pipeline that maps `core.threat_intel.models.ScoredIOC`s to ATT&CK techniques (rule-based, deterministic), aggregates supporting evidence, calculates multi-dimensional confidence, assigns severity/priority/risk score, deduplicates/merges within a case, and persists typed `Finding` records — plus the concrete MITRE ATT&CK knowledge layer (`core/knowledge/mitre/`) ADR-0010 deferred, and the third/fourth real domain schemas (`Finding`/`FindingMitreMapping` and five MITRE reference tables). Built ahead of the milestone schedule (normally split across M2's "MITRE mapping" half and M4's remaining specialist-agent work) at explicit user direction — framework-first, extending the exact precedent set by the Multi-Agent Framework (ADR-0009), Memory & Knowledge Layer (ADR-0010), Evidence Ingestion & Parser Framework (ADR-0011), and Threat Intelligence & IOC Extraction Framework (ADR-0012) sessions. Full design rationale, including six deliberate architecture decisions and mid-implementation refinements: `docs/adr/0013-finding-mitre-intelligence-engine-shape.md`.

### M0 foundation + Multi-Agent Framework + Memory & Knowledge Layer + Evidence Ingestion Framework + Threat Intelligence Framework (unchanged from prior sessions)

- **Configuration, logging, shared contracts, DB foundation, FastAPI app, governance, `core/agents`/`core/tools`/`core/graph` framework, `core/memory`/`core/knowledge` framework, `core/parsers` framework (9 parsers) + `Evidence` domain table, `core/threat_intel` framework (20 IOC types) + `IOC` domain table, `core/services/{evidence_service,threat_intel_service}.py`** — unchanged, see prior sessions' detail in git history / `docs/adr/0001-0012`.

### Finding & MITRE ATT&CK Intelligence Engine (new this session)

- **`data/mitre/raw/attack-enterprise-15.1.json`** — a genuine STIX 2.1 bundle, but a curated, hand-authored subset of the official MITRE ATT&CK Enterprise matrix (not the complete corpus, documented honestly): all 14 Enterprise tactics, 20 real well-known techniques, 5 real software entries, 5 real groups, 6 real mitigations, ~39 real `uses`/`mitigates` relationships — every ID/name/relationship is real MITRE taxonomy; only the STIX object UUIDs are session-generated. `data/mitre/README.md` documents provenance and the versioned import path for a future/complete official bundle. **Never fetched over the network** — the application works completely offline.
- **`core/knowledge/mitre/`** — fulfills ADR-0010's deliberately deferred `KnowledgeSourceType.MITRE_ATTACK` slot: `models.py` (`MitreTactic`, `MitreTechnique`, `MitreSoftware`, `MitreGroup`, `MitreMitigation`, `MitreRelationship`, `MitreDataset`, all versioned via `attack_spec_version`), `exceptions.py` (`MalformedMitreDataError`, `UnknownTechniqueError`, `UnsupportedAttackVersionError`), `loader.py` (`load_bundle`/`load_bundle_from_path`: the one STIX-parsing implementation, reused by both the in-memory source and the DB seed script; a malformed *individual* object is skipped and logged, never a hard failure — only a structurally invalid bundle raises), `source.py` (`MitreAttackSource`, a concrete `KnowledgeSource`), `lookup.py` (`MitreLookup`: `technique_by_id`, `tactics_for_technique`, `mitigations_for_technique`, `groups_using_technique`, `software_using_technique`), `bootstrap.py` (`load_mitre_dataset(settings)`, validates the vendored bundle's version against `Settings.mitre_attack_version`).
- **`core/findings/`** (new leaf package, peer to `core/threat_intel`/`core/parsers`) — `models.py` (`FindingSeverity`, `FindingStatus`, `FindingPriority`, `MappingConfidenceFactors`, `MitreMapping`, `TimelineEntry`, `EvidenceBundle`, `FindingConfidence`, `DuplicateMatchResult`, `FindingRecord`), `exceptions.py` (`FindingsError`, `NoTechniqueMatchError`, `InvalidMappingRuleError`, `DuplicateExplosionGuardError`), `base.py` (`BaseFindingGenerator`, template-method base mirroring `BaseIOCExtractor`), `mapping_rules.py` (`MAPPING_RULES`: twenty data-driven rules, one per vendored technique, supporting both one-IOC-to-many-techniques — e.g. `USERNAME` maps to both Brute Force and Valid Accounts — and many-IOCs-to-one-technique via co-occurrence boosting), `mapping_engine.py` (`MitreMappingEngine`, the one concrete rule-dispatching mapper; validates every rule's `technique_id` against the loaded `MitreDataset` at construction time, never mid-evaluation; returns "unmapped" — never a forced low-confidence guess — for anything below `finding_mapping_min_confidence`), `evidence_aggregation.py` (`EvidenceAggregator`: cross-reference tracking, timeline reconstruction, chain-of-custody preservation via carried-forward `AttributionRecord`s), `confidence_engine.py` (`ConfidenceEngine`/`FindingConfidenceWeights`, all seven required dimensions — IOC quality, evidence quality, supporting-indicator count, rule strength, mapping quality, source reliability, historical evidence [a documented neutral stub pending cross-case memory] — weights sum-to-1.0 validated), `severity.py` (pure `assign_severity`/`assign_priority`/`calculate_risk_score` functions), `dedup.py` (`FindingDeduplicationEngine`: the six required dimensions — hash similarity, IOC overlap, technique overlap, evidence overlap, time-window proximity, host overlap — bucket-first pre-filtering for performance and a technique-overlap gate that prevents two Findings mapped to disjoint techniques from ever merging, however much supporting evidence otherwise overlaps; `merge_findings()`, which unions evidence/IOCs/mappings and reopens a `CLOSED` merge target), `finding_generator.py` (`FindingGenerationEngine`: one candidate Finding per mapped technique), `metrics.py`/`events.py`/`audit.py` (self-contained, leaf-layer observability, never importing `core.graph.events.EventBus`; `events.py` defines the six required lifecycle events — `FindingCreated`, `FindingUpdated`, `FindingMerged`, `TechniqueMapped`, `ConfidenceUpdated`, `FindingClosed`).
- **`core/db/models/{mitre_tactic,mitre_technique,mitre_software,mitre_group,mitre_mitigation}.py`** — five reference tables, each with a surrogate UUID PK (never the business ID, per constitution §7), a unique indexed `(business_id, attack_spec_version)` pair, seeded **only** by `scripts/mitre/import_attack_bundle.py`, never by application logic. **`core/db/models/finding.py`** (`Finding` + `FindingStatus`; `case_id` a plain UUID column pending Milestone M1's `Case` model, following the exact `Evidence.case_id`/`IOC.case_id` precedent; `primary_evidence_id`/`primary_ioc_id` real nullable FKs to `evidence.id`/`iocs.id`; `finding_data_json` stores the full serialized `FindingRecord`) and **`core/db/models/finding_mitre_mapping.py`** (`FindingMitreMapping`, the real many-to-many join table — one Finding maps to several techniques, one technique is shared across many Findings). Plus `core/db/finding_repository.py` and `core/db/mitre_repository.py` (five small per-table repositories), and two hand-reviewed Alembic migrations (`873a0801082d_create_mitre_reference_tables.py`, `0db9628cc4fc_create_finding_and_finding_mitre_.py`, generated via `alembic revision --autogenerate` and verified end-to-end against a throwaway SQLite DB — every table, index, unique constraint, and FK confirmed present, including the full migration chain applied cleanly from empty DB to head).
- **`core/services/finding_service.py`** — `FindingGenerationPipeline`, the explicit stages requested — `discover` → `map_and_generate` → `deduplicate` → `persist` → `publish_event` → `notify_memory` — composed by one `generate_findings_for_case()` orchestrator, plus `get_finding()`/`list_findings_for_case()`. `discover()` reconstructs `ScoredIOC`s from `IOC.metadata_json` (never re-extracts), excluding non-`ACTIVE` rows. `persist()` explicitly sets `Finding.id = FindingRecord.finding_id` so the persisted row and its embedded JSON blob share one identity (load-bearing for merge-target lookup). A missing `MitreTechnique` seed row degrades to a skipped, logged join-table insert — never a crash. `notify_memory` is advisory-only, verified by test.
- **`scripts/mitre/import_attack_bundle.py`** — the only supported way ATT&CK data enters the system: reads a local vendored STIX bundle (`--bundle`), seeds the five reference tables, idempotent (skips rows already present for a `(business_id, attack_spec_version)` pair), never fetches over the network. Verified end-to-end against a fresh SQLite DB (full migration chain + real seed: 14 tactics, 20 techniques, 5 software, 5 groups, 6 mitigations).
- **New `Settings` fields**: `mitre_attack_data_path`, `mitre_attack_version`, `finding_mapping_min_confidence`, `finding_dedup_similarity_threshold`, `finding_dedup_time_window_minutes`, `finding_max_candidates_per_case` — all documented in `.env.example`.
- **New mermaid diagrams**: `docs/diagrams/finding-mitre-mapping-pipeline.mmd` (the Finding Generation Pipeline sequence), `finding-lifecycle.mmd` (one candidate `FindingRecord`'s state machine: mapped → aggregated → scored → deduplicated → open/merged/closed).
- **Testing** — 112 new tests (629 total, up from 517): dedicated `tests/unit/test_mitre_*.py`/`test_findings_*.py` files (one per module, 20 files total across both packages), `test_db_finding_repository.py`/`test_db_mitre_repository.py` (real SQLite), `test_finding_service.py` (full pipeline against hand-built fixtures — happy path, no-mappable-IOCs, second-run merge, missing-technique-seed degradation, dismissed-IOC exclusion, memory-advisory-failure, a 300-IOC performance guard), `test_import_attack_bundle_script.py` (idempotency), and `tests/integration/test_finding_mitre_pipeline_integration.py` (the *real* vendored bundle + the *real* default `MAPPING_RULES` table + the real seed script together — a mapping-rules/dataset consistency test, a rejected-bad-rule test, a full end-to-end generation test, and a 500-IOC performance guard). mypy (strict on `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py` all pass; the new `core/findings`/`core/knowledge/mitre` leaf boundaries and the `core/services → core/findings`/`core/knowledge`/`core/threat_intel` edge were verified by manual `grep` to be exactly as scoped in the ADR.
- **No new runtime dependency** — `core/findings` and `core/knowledge/mitre` use only the stdlib (`json`, `hashlib`, `uuid`, `datetime`) plus existing Pydantic/SQLAlchemy.

**Explicitly NOT built, by this session's stated scope:** `Case`/`MitreTechnique`-as-blueprint-flat-table (superseded by the five-table schema)/`TimelineEvent`/`Report` domain models beyond `Finding`, any concrete specialist agent (SOC Analyst, Threat Hunting, Phishing, Vulnerability, OWASP, Linux Security, Incident Response, MITRE Mapping), any LLM reasoning, any cross-case/incident correlation, any `/api/v1` route, `email_parser.py`/`nessus_parser.py`/`openvas_parser.py`/`source_code_parser.py`/`incident_parser.py`, `core/security/*`, `core/reporting/*`, any `apps/web` code, and the complete official MITRE ATT&CK STIX corpus (a curated real-data subset is vendored; the import script supports importing the full bundle later without any code change).

---

## Repository Status

```
apps/
  api/            FastAPI app (unchanged)                          [implemented]
  web/             Streamlit frontend                               [README only]
core/
  config/         settings.py + mitre_*/finding_* fields NEW        [implemented]
  logging/        (unchanged)                                       [implemented]
  exceptions.py, schemas.py, interfaces.py                          [implemented]
  agents/         (unchanged — framework only)                      [implemented — framework only]
  tools/          (unchanged — framework only)                      [implemented — framework only]
  memory/         (unchanged — framework only)                      [implemented — framework only]
  knowledge/      abstraction (unchanged) + mitre/ (NEW, 7 modules)  [implemented — abstraction + 1 concrete source]
  graph/          (unchanged — framework only)                       [implemented — framework only]
  db/             base_repository.py, session.py (unchanged) +
                   models/ (evidence.py, ioc.py, finding.py NEW,
                   finding_mitre_mapping.py NEW, mitre_tactic.py NEW,
                   mitre_technique.py NEW, mitre_software.py NEW,
                   mitre_group.py NEW, mitre_mitigation.py NEW),
                   evidence_repository.py, ioc_repository.py,
                   finding_repository.py (NEW), mitre_repository.py (NEW),
                   migrations/versions/ (+2 NEW)                    [implemented — 4 real domain tables + 5 reference tables]
  parsers/        (unchanged — 9 parsers + framework)                [implemented — 9 parsers + framework]
  threat_intel/   (unchanged — 20 modules)                           [implemented]
  findings/       models.py, exceptions.py, base.py, mapping_rules.py,
                   mapping_engine.py, evidence_aggregation.py,
                   confidence_engine.py, severity.py, dedup.py,
                   finding_generator.py, metrics.py, events.py,
                   audit.py                                          [NEW — implemented, 13 modules]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       evidence_service.py, threat_intel_service.py,
                   finding_service.py (NEW); case_service.py,
                   report_service.py                                 [implemented — evidence + threat intel + findings]
data/
  sample_evidence/ (unchanged — 9 fixtures + malformed/)             [unchanged]
  mitre/          raw/attack-enterprise-15.1.json (NEW), README.md (NEW) [NEW — implemented, curated subset]
scripts/
  mitre/          import_attack_bundle.py (NEW)                      [NEW — implemented]
tests/
  unit/           101 test modules (608 tests total, +18 modules/+108 tests this session)
  integration/    5 test modules (21 tests, +1 module/+4 tests this session)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (14 ADR files incl. template) +
                   docs/diagrams/ (+2 new .mmd files)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          run_migrations.sh, seed_sample_data.py, check_dependency_rules.py, mitre/ (NEW)
.github/          (unchanged)
```

629 tests passing as of this session (517 prior → 629 now: 112 new). This session added: 7 new `core/knowledge/mitre/` modules, 13 new `core/findings/` modules, 7 new `core/db/models/` files + 2 new `core/db/` repository files + 2 new Alembic migrations, 1 new `core/services/` file, 1 new `scripts/mitre/` script, 19 new test files (18 unit + 1 integration) + 1 new test-helper module, 1 new ADR, 2 new diagrams, 1 new vendored data file + its README, plus edits to `core/config/settings.py`, `.env.example`, `core/db/models/__init__.py`, `docs/dependency-rules.md`, `docs/roadmap.md`, `docs/diagrams/README.md`, `core/db/README.md`, `core/knowledge/README.md`, `core/services/README.md`, `scripts/README.md`, `CHANGELOG.md`, and this file — all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` and `context/03_constitution.md` still do not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0009/0010/0011/0012 per ADR-0013's explicit scoping. Six deliberate decisions, all documented in `docs/adr/0013-finding-mitre-intelligence-engine-shape.md`:

1. **The concrete MITRE reference-data/model layer lives in `core/knowledge/mitre/`**, fulfilling ADR-0010's deferred `KnowledgeSourceType.MITRE_ATTACK` slot — not a second, competing model layer inside the new Finding package.
2. **`core/findings/` is a new leaf package, peer to `core/threat_intel`/`core/parsers`.** May import `core.knowledge` (already permitted) and, as a new documented sideways leaf-model exception matching `core/threat_intel`'s import of `core.parsers.models`, `core.threat_intel.models` (its input contract only). `docs/dependency-rules.md` rule 5 extended accordingly.
3. **`core/services/finding_service.py` gets rule "4c"** — the third documented exception to "services only call `core/graph`," worded identically to 4a/4b.
4. **The official MITRE ATT&CK corpus is vendored locally, a curated real-data subset for this session**, with `scripts/mitre/import_attack_bundle.py` as the versioned, code-change-free import path for a future/complete bundle. Never fetched over the network.
5. **Every MITRE reference table's business ID (`technique_id`, etc.) is a unique indexed column, never the primary key** — constitution §7's explicit rule, restated because MITRE IDs look permanently stable.
6. **`Finding.case_id` is a plain UUID column, not a foreign key** — `Case` still doesn't exist, following the exact `Evidence.case_id`/`IOC.case_id` precedent. `Finding.primary_evidence_id`/`primary_ioc_id` and `FindingMitreMapping`'s two FKs **are** real, since their referenced tables already exist.

Plus all architectural notes carried forward unchanged from prior sessions (see git history for ADR-0001 through 0012's individual points). No approved architectural decision has been reversed. `docs/roadmap.md`'s M2 checkbox remains unchecked — the MITRE knowledge layer's concrete data and the full Finding Engine are implemented, but M2's own demo criterion (two independent working modules through a real agent) needs a concrete MITRE Mapping Agent and the Phishing Investigation Agent first; M4's checkbox likewise remains unchecked pending the concrete Vulnerability/OWASP/Linux/Threat Hunting agents.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **`core/findings`/`core/knowledge/mitre` reuse existing patterns rather than inventing new ones.** `BaseFindingGenerator` is `BaseIOCExtractor`'s template-method shape applied once more; `core/findings/metrics.py`/`events.py`/`audit.py` mirror `core/threat_intel`'s identical "self-contained, no `EventBus`" pattern; `MitreAttackSource` satisfies the `KnowledgeSource` Protocol ADR-0010 already defined.
- **One data-driven `MAPPING_RULES` table, not twenty near-duplicate per-technique mapper classes** — `MitreMappingEngine` dispatches from `mapping_rules.py` exactly as `IOCExtractionEngine` dispatches from `patterns.py` (ADR-0012's precedent, reapplied).
- **Dedup's "empty vs. empty" Jaccard convention was corrected during implementation**: two Findings both lacking, say, linked evidence artifacts score 1.0 on that dimension (agreement, not disagreement) — discovered via a failing merge test where a legitimately-duplicate second-run candidate wasn't merging because every empty-vs-empty comparison scored 0.0 and dragged the average down. Documented in `dedup.py::_jaccard`'s docstring.
- **Dedup gates merging on technique overlap**: two candidates mapped to entirely disjoint technique sets are never merge candidates, however much supporting evidence otherwise overlaps — discovered via a failing test where two legitimately-separate Findings (one IOC mapped to two different techniques in the same generation run) were incorrectly merging into one. This is the structural expression of "one-IOC-to-many-techniques stays separate."
- **`Finding.id` (the DB surrogate PK) is explicitly set to `FindingRecord.finding_id`** rather than left to `Entity`'s default factory — the persisted row and its embedded JSON blob must share one identity, since dedup/merge logic reasons about "this Finding" purely in terms of `FindingRecord.finding_id`.
- **Finding confidence weights are configurable and validated to sum to 1.0** (`FindingConfidenceWeights`), mirroring `ThreatScoringEngine`'s identical pattern — the task's explicit "do not hardcode scoring values" requirement, structurally enforced.
- **The vendored MITRE bundle is an honest, curated subset**, not the complete official corpus — documented explicitly in `data/mitre/README.md` and ADR-0013, with a real, tested, code-change-free import path (`scripts/mitre/import_attack_bundle.py`) for importing the complete bundle later.
- **No FastAPI route this session** — mirrors ADR-0011/0012's identical scope cut; `Case` doesn't exist yet.

---

## Public Interfaces

*(M0/M3/M6/M1-evidence/M4-threat-intel interfaces — unchanged from prior sessions except as noted below.)*

**MITRE knowledge contracts:** `core.knowledge.mitre.models.{MitreObjectType, MitreRelationshipType, MitreTactic, MitreTechnique, MitreSoftware, MitreGroup, MitreMitigation, MitreRelationship, MitreDataset}`, `core.knowledge.mitre.exceptions.{MitreKnowledgeError, MalformedMitreDataError, UnknownTechniqueError, UnsupportedAttackVersionError}`, `core.knowledge.mitre.loader.{load_bundle, load_bundle_from_path}`, `core.knowledge.mitre.source.MitreAttackSource`, `core.knowledge.mitre.lookup.MitreLookup`, `core.knowledge.mitre.bootstrap.load_mitre_dataset`.

**Findings contracts:** `core.findings.models.{FindingSeverity, FindingStatus, FindingPriority, DedupDecision, MappingConfidenceFactors, MitreMapping, TimelineEntry, EvidenceBundle, FindingConfidence, DuplicateMatchResult, FindingRecord}`, `core.findings.exceptions.{FindingsError, NoTechniqueMatchError, InvalidMappingRuleError, DuplicateExplosionGuardError}`, `core.findings.base.{BaseFindingGenerator, MappingRunResult}`.

**Findings framework:** `core.findings.mapping_rules.{MappingRule, MAPPING_RULES}`, `core.findings.mapping_engine.MitreMappingEngine`, `core.findings.evidence_aggregation.EvidenceAggregator`, `core.findings.confidence_engine.{FindingConfidenceWeights, ConfidenceEngine}`, `core.findings.severity.{assign_severity, assign_priority, calculate_risk_score}`, `core.findings.dedup.{FindingDeduplicationEngine, merge_findings}`, `core.findings.finding_generator.FindingGenerationEngine`, `core.findings.metrics.FindingsMetricsCollector`, `core.findings.events.{FindingEvent, FindingEventType, FindingEventPublisher}`, `core.findings.audit.{FindingAuditAction, log_finding_audit_event}`.

**Domain persistence:** `core.db.models.{Evidence, EvidenceStatus, IOC, IOCStatus, Finding, FindingMitreMapping, MitreTactic, MitreTechnique, MitreSoftware, MitreGroup, MitreMitigation}`, `core.db.evidence_repository.EvidenceRepository`, `core.db.ioc_repository.IOCRepository`, `core.db.finding_repository.FindingRepository`, `core.db.mitre_repository.{MitreTacticRepository, MitreTechniqueRepository, MitreSoftwareRepository, MitreGroupRepository, MitreMitigationRepository}`.

**Finding service:** `core.services.finding_service.{FindingGenerationPipeline, FindingGenerationResult, generate_findings_for_case, get_finding, list_findings_for_case}`.

**Seed script:** `scripts.mitre.import_attack_bundle.{import_dataset, main}`.

No `Case`/`TimelineEvent`/`Report` models/schemas, concrete specialist agents, concrete `ThreatIntelProvider`/`IOCEnrichmentProvider` implementations, or `/api/v1` routes exist as public interfaces yet.

---

## Remaining Work

Unchanged in substance from the prior session's plan (see `docs/roadmap.md`), except M2's MITRE-mapping half and part of M4 are now done ahead of schedule:

1. **M1 — remaining piece.** `Case`/`TimelineEvent`/`Report` domain models + their Alembic migration (including follow-up migrations turning `Evidence.case_id`, `IOC.case_id`, and `Finding.case_id` into real FKs); `core/tools/scoring.py`; `core/agents/soc_analyst_agent.py`; first real `/api/v1` route wiring `evidence_service`/`case_service`/`threat_intel_service`/`finding_service` together.
2. **M2 — remaining piece.** Phishing Investigation Agent + `email_parser.py` + `core/security/prompt_guard.py`; a concrete `core/agents/mitre_mapping_agent.py` (or extended `threat_hunter_agent.py`) that calls `core.services.finding_service.generate_findings_for_case()` and reasons over its typed output — the same "framework built, agent still unbuilt" pattern ADR-0011/0012 established.
3. **M3 — remaining piece:** wire real agents through the now-implemented framework.
4. **M4 — remaining piece.** Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent, Linux Security Agent, `core/agents/threat_hunter_agent.py`.
5. **M5 — Incident Response synthesis + Reporting.**
6. **M6 — remaining piece:** swap `InMemoryVectorStore` for real ChromaDB, populate remaining knowledge data (OWASP, playbooks), Threat Timeline/MITRE heatmap/AI Analyst Chat UI.
7. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md`/`03_constitution.md` don't exist; `make migrate`/`make seed` are no-ops for `Case`; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix — manually verified via `grep` for each new session's boundaries; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is not semantic; numpy not installed; `windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`.)*

- **`Evidence.case_id`, `IOC.case_id`, and `Finding.case_id` have no referential integrity yet** (plain UUID, no FK) — resolved when Milestone M1 adds `Case` and its follow-up FK migration for all three tables.
- **No `/api/v1` route exists for Findings** — `generate_findings_for_case()` is only callable from `core/services` directly, not yet from `apps/api` or `apps/web`.
- **The vendored MITRE ATT&CK bundle is a curated subset (20 techniques, 14 tactics, 5 software, 5 groups, 6 mitigations), not the complete official corpus** — a deliberate, documented scope choice (`data/mitre/README.md`); mapping coverage is bounded by which techniques were vendored, not by the mapping engine's design, which is unchanged by importing a larger bundle via `scripts/mitre/import_attack_bundle.py`.
- **`core/findings`'s Finding-clustering strategy is "one candidate per mapped technique"** — a deliberate, simple, deterministic choice (`core/findings/README.md`/`finding_generator.py` docstring) rather than connected-components clustering across shared IOCs; a future milestone could refine this without changing any downstream consumer's contract.
- **`ConfidenceEngine`'s `historical_evidence` dimension is a documented neutral stub (0.5)** — no cross-case memory exists yet; a future Memory Agent supplies a real value through the same parameter without a signature change.
- **No MITRE relationship data is persisted to the database** — `MitreRelationship` (uses/mitigates edges) exists only in the in-memory `MitreDataset`/`MitreLookup` the mapping engine reads directly; there is no `mitre_relationships` table. This was a deliberate scope choice (not requested as a persisted, queryable table) but is worth flagging if a future UI wants to query relationships independently of the mapping engine.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependency this session** — `core/findings` and `core/knowledge/mitre` use only the stdlib (`json`, `hashlib`, `uuid`, `datetime`, `pathlib`) plus already-present Pydantic/SQLAlchemy.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`), with five prior commits: `eae4fb8` (foundation) → `0ee65d5` (memory/knowledge) → `8664039` (parsers) → `40ac180` (threat intel) → `908e34a` (mypy --strict hardening). All prior-session work is committed — the working tree was clean at the start of this session.

This session's Finding & MITRE ATT&CK Intelligence Engine work added/modified (all currently uncommitted):
- New: `docs/adr/0013-finding-mitre-intelligence-engine-shape.md`, `data/mitre/raw/attack-enterprise-15.1.json`, `data/mitre/README.md`, `core/knowledge/mitre/*` (7 files), `core/findings/*` (13 files + README), `core/db/models/{finding,finding_mitre_mapping,mitre_tactic,mitre_technique,mitre_software,mitre_group,mitre_mitigation}.py`, `core/db/finding_repository.py`, `core/db/mitre_repository.py`, `core/db/migrations/versions/{873a0801082d,0db9628cc4fc}_*.py`, `core/services/finding_service.py`, `scripts/mitre/import_attack_bundle.py`, `docs/diagrams/{finding-mitre-mapping-pipeline,finding-lifecycle}.mmd`, 21 new test files.
- Modified: `core/config/settings.py`, `.env.example`, `core/db/models/__init__.py`, `docs/dependency-rules.md`, `docs/roadmap.md`, `docs/diagrams/README.md`, `core/db/README.md`, `core/knowledge/README.md`, `core/services/README.md`, `scripts/README.md`, `CHANGELOG.md`, `context/current_state.md` (this file).

Full suite (629 tests), `ruff check`/`format`, `mypy core --strict` (whole `core/`), and `scripts/check_dependency_rules.py` all pass. Every new package boundary (`core/findings`, `core/knowledge/mitre`, `core/services/finding_service.py`'s rule-4c imports) was manually `grep`-verified against the ADR's documented scope. Commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement the remaining piece of Milestone M1 exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: add `core/db/models/case.py` (and `timeline_event.py`, `report.py`) defining `Case`, `TimelineEvent`, and `Report` (each inheriting `core.db.Entity`, per `context/01_blueprint.md` §8 and `context/03_engineering_constitution.md` §7), generate the Alembic migration against them (including follow-up migrations that turn `Evidence.case_id`, `IOC.case_id`, and `Finding.case_id` into real foreign keys against the new `Case` table — additive, per constitution §7), implement `core/tools/scoring.py` as a concrete `BaseTool` subclass, and implement `core/agents/soc_analyst_agent.py` as a concrete `BaseAgent` subclass — constructed with a real `core.memory.case_memory.SQLiteCaseMemory` rather than `None` — registered into `AgentRegistry` and wired into `core/graph/investigation_graph.py`. Wire `core.services.evidence_service.ingest_evidence()`, `core.services.threat_intel_service.extract_threat_intelligence()`, `core.services.finding_service.generate_findings_for_case()`, and a new `core.services.case_service` together, and add the first real `/api/v1` routes (`apps/api/routers/cases.py`, `evidence.py`, `iocs.py`, and/or `findings.py`) so a case can actually be created, have evidence uploaded, have IOCs extracted, and have Findings generated end-to-end. Do not build the OWASP/Vulnerability/Phishing/Threat-Hunting/MITRE-Mapping agents yet, and do not populate any OWASP/playbook knowledge data yet — those are later milestones. Preserve every existing file and architectural decision described in this document, including the Multi-Agent Framework, the Memory & Knowledge Layer, the Evidence Ingestion & Parser Framework, the Threat Intelligence & IOC Extraction Framework, and the Finding & MITRE ATT&CK Intelligence Engine built in prior sessions; only extend them.
