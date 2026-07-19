# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once
`v1.0.0` is tagged. Pre-1.0 releases are tagged per milestone
(`v0.1-foundation`, `v0.2-single-agent`, ...) as described in
`docs/roadmap.md`.

## [Unreleased]

### Added
- Repository foundation: full directory skeleton with per-folder purpose
  documentation, root engineering/config files, documentation set (including
  ADRs 0001–0008), GitHub governance files, and realistic sample evidence
  fixtures.
- `context/03_engineering_constitution.md`: the binding, project-wide
  engineering standard every future implementation must follow.
- Backend engineering foundation (no domain/business logic yet):
  - `core/config`: pydantic-settings `Settings`, `Environment`/`LLMProvider`
    enums, cached `get_settings()`.
  - `core/logging`: structlog + stdlib logging integration (JSON in
    production, console in dev/test, rotating file handler), request/case/
    agent/correlation-ID context binding, `log_execution_time` decorator.
  - `core/exceptions`, `core/schemas`, `core/interfaces`: shared exception
    hierarchy, API error/pagination/health envelopes, and `Repository`/
    `Agent`/`Tool` structural Protocols.
  - `core/graph/state.py`: minimal `CaseInvestigationState` (no agent logic).
  - `core/db`: async SQLAlchemy engine/session management, `Entity` base
    (surrogate UUID primary key convention), generic `BaseRepository`,
    Alembic migration scaffolding wired to async settings.
  - `apps/api`: FastAPI application factory, request-context middleware,
    standardized exception handlers, `/health`, `/ready`, `/version`
    endpoints, OpenAPI customization, auth/dependency-injection placeholders.
  - 72 tests (unit + integration), 98% coverage on all new code; mypy, ruff,
    and the `core/` dependency-rule check all pass.
- Multi-Agent Framework (`docs/adr/0009-multi-agent-framework-shape.md`) —
  the reusable agent/tool/workflow infrastructure, built ahead of the
  milestone schedule as pure framework with zero cybersecurity domain
  logic and no concrete specialist agent:
  - `core/agents`: `BaseAgent` (template-method lifecycle: identity,
    validation, tool/memory access, ReAct thought/confidence, structured
    logging, typed error handling), `AgentRegistry`, `ConfidenceScore`/
    `ConfidenceLevel`, the framework's shared Pydantic contracts
    (`ExecutionPlan`, `AgentExecutionResult`, `AgentCapability`, ...),
    `CoordinatorAgent` (delegates planning, never executes agents itself),
    `PlanningAgent` (capability-matching plan builder).
  - `core/tools`: `BaseTool` (template-method: validation, timeout,
    permission checks, bounded retry on I/O-bound tools only, caching,
    logging) and `ToolRegistry`.
  - `core/memory/interfaces.py`: `ShortTermMemory`/`CaseMemory`/
    `LongTermMemory`/`VectorMemory` Protocols — abstraction only, no
    implementation.
  - `core/graph`: `WorkflowEngine` (compiles registered agents into a real
    LangGraph `StateGraph`, with retry/failure-recovery/event-publication/
    metrics wired uniformly around every node), `routing.py`
    (`route_from_coordinator`), `investigation_graph.py`
    (`build_investigation_graph`/`run_investigation`), `events.py`
    (`EventBus`), `retry.py` (`RetryPolicy`), `failure_recovery.py`
    (`FailureRecoveryPolicy`), `metrics.py` (`MetricsCollector`),
    `execution_context.py`. `CaseInvestigationState` extended with
    `execution_plan`, `agent_outputs`, `confidence_scores`,
    `intermediate_results`, `execution_history`, `errors`, `metadata`,
    `extensions`, `extracted_indicators` — list/dict fields use
    `Annotated` reducers so independent agents can run in the same
    LangGraph superstep without conflicting (verified against the
    installed `langgraph` package's actual parallel-fanout behavior, which
    surfaced and fixed a real double-write bug before it reached the test
    suite — see the ADR).
  - 86 new tests (158 total), full mypy/ruff/dependency-rule pass. Added
    `langgraph` as an installed, actively-imported dependency (previously
    pinned in `requirements.txt` but unused).
  - `docs/dependency-rules.md` clarified: `core/agents` may import
    `core/graph/state.py` specifically (a shared state *contract*, not
    graph business logic) — a pre-existing gap between the constitution's
    literal agent-signature requirement and the dependency matrix, closed
    explicitly rather than left implicit.
- Memory & Knowledge Layer (`docs/adr/0010-memory-knowledge-layer-shape.md`)
  — built ahead of the milestone schedule (normally M6) as pure
  infrastructure, with zero cybersecurity domain logic and no populated
  knowledge data:
  - `core/memory/models.py`: `MemoryScope`/`MemoryPriority`/`MemoryRecord`/
    `MemoryQuery`/`MemoryQueryResult`/`ConversationTurn` typed contracts.
  - `core/memory/db_models.py` + `repository.py`: SQLite persistence for
    memory records via `core.db.BaseRepository`, indexed on
    `(scope, case_id)`, with scope/case/text/tag filtering and
    expiry-based bulk deletion.
  - Concrete implementations of every existing memory Protocol:
    `SessionMemory` (`ShortTermMemory`), `SQLiteCaseMemory` (`CaseMemory`,
    the first real backing for `BaseAgent`'s existing
    `case_memory` constructor parameter), `InMemoryVectorStore` +
    `NullVectorStore` (`VectorMemory` — a genuinely working brute-force
    cosine-similarity store plus a documented no-op fallback; ChromaDB
    itself remains M6, unbuilt, per ADR-0005/0006), `LongTermMemoryManager`
    (`LongTermMemory`, always-advisory per ADR-0006), and a new
    `ConversationMemory` Protocol + `InMemoryConversationMemory`
    implementation for case-scoped chat history.
  - `core/memory/vector_store.py` also ships a deterministic,
    dependency-free `HashingTextEmbedder` (`TextEmbedder` Protocol) so the
    vector store is exercisable end-to-end without an LLM provider call.
  - `core/memory/lifecycle.py`: `MemoryLifecycleManager` — per-scope TTL
    defaults and a `cleanup_expired()` pass, the reusable unit a future
    scheduled job calls.
  - `core/memory/context_builder.py` + `context_serializer.py`: filter →
    deduplicate → rank (priority, then recency) → truncate-to-budget
    context assembly, rendered to prompt text or a structured dict.
  - `core/memory/metrics.py`: self-contained `MemoryMetricsCollector`
    (hit/miss/write/eviction counters, retrieval timing) — deliberately
    independent of `core.graph.events.EventBus` since `core/memory` is a
    leaf layer that must never import `core/graph`.
  - `core/memory/registry.py` + `manager.py`: `MemoryRegistry` (generic
    named-backend lookup) and `MemoryManager` (the single facade wiring
    session/case/conversation/long-term memory, context assembly, and
    metrics together — every dependency optional and injected, degrading
    to advisory no-ops with nothing configured).
  - `core/knowledge/models.py`, `interfaces.py`, `registry.py`,
    `retrieval.py`: `KnowledgeSourceType` (MITRE/OWASP/threat-intel/
    playbook/detection-rule/investigation-template — no data populated),
    `KnowledgeSource`/`KnowledgeRetriever` Protocols,
    `KnowledgeSourceRegistry`, and a deterministic
    `KeywordKnowledgeRetriever`.
  - 70 new tests (228 total), full mypy/ruff/dependency-rule pass.
- Evidence Ingestion & Parser Framework
  (`docs/adr/0011-evidence-ingestion-pipeline-shape.md`) — built ahead of
  the milestone schedule (normally part of M1) as reusable, agent-independent
  infrastructure, with zero investigation/MITRE/agent logic:
  - `core/parsers/models.py`: the canonical evidence contract —
    `EvidenceType`, `Severity`, `EvidenceRecord` (per-event), `NormalizedEvidence`
    (per-artifact container with `ChainOfCustody`), every parser's one output shape.
  - `core/parsers/base.py`: `BaseParser` template method (mirrors
    `BaseTool`/`BaseAgent`'s shape) — owns encoding detection, fingerprinting,
    timing, metrics, logging, and the degrade-not-crash contract
    (a malformed artifact returns a zero-confidence result with the whole
    artifact preserved in `unparsed_fragments`, never a crash and never
    silently dropped data).
  - `core/parsers/registry.py`: plugin-capable `ParserRegistry` — aliases,
    versioning, priority-based tie-breaking, enable/disable, and
    `load_plugins()` via `importlib.metadata` entry points (`cdc.parsers`
    group) as a real, working external-extension seam.
  - `core/parsers/factory.py`: deterministic `select_parser` (declared type
    → extension → content-sniff ranking → `UnsupportedFormatError`).
  - `core/parsers/detection.py`, `validation.py`, `fingerprint.py`: stdlib-only
    MIME/encoding detection (no `chardet`/`python-magic` dependency added),
    upload-boundary validation (size caps, extension allowlist, path-traversal
    guard), and SHA-256 fingerprinting.
  - `core/parsers/metrics.py`, `events.py`, `audit.py`: self-contained parser
    metrics/event-publisher (independent of `core.graph.events.EventBus`, per
    the same leaf-layering reasoning as `core/memory/metrics.py`), and
    structured chain-of-custody audit logging.
  - Nine concrete parsers, each a `BaseParser` subclass: `ssh_auth`,
    `apache_access`, `apache_error`, `syslog` (generic RFC3164-ish fallback),
    `windows_event` (a CSV/XML **EVTX abstraction** — binary `.evtx` parsing
    is a documented future extension), `json_evidence`, `csv_evidence`,
    `nmap_xml` (via `defusedxml` — XXE/entity-expansion-safe, verified against
    an XXE-attempt fixture), `plain_text` (deterministic last-resort fallback).
  - `core/db/models/` (new package, first domain persistence): `Evidence`
    ORM model + `EvidenceStatus`, `case_id` a plain UUID column pending
    Milestone M1's `Case` model (extending the exact ADR-0010 precedent),
    plus its first Alembic migration and `core/db/evidence_repository.py`
    (`find_by_case`, `find_by_sha256` dedup, `mark_parsed`, `mark_failed`).
  - `core/services/evidence_service.py`: `EvidencePipeline`, the ten explicit
    stages (upload → validate → fingerprint → extract_metadata →
    select_parser → parse → normalize → persist → publish_event →
    notify_memory) + `ingest_evidence()` orchestrator. `core/services`
    importing `core/parsers`/`core/memory` directly is a documented,
    scoped exception to the "services only call `core/graph`" rule (ADR-0011),
    since evidence ingestion is deterministic and pre-investigation.
  - Two new mermaid diagrams (`docs/diagrams/evidence-ingestion-pipeline.mmd`,
    `parser-lifecycle.mmd`).
  - 107 new tests (352 total, up from 245), including adversarial fixtures
    (an XXE-attempt Nmap XML, truncated/malformed CSV and JSON, path
    traversal filenames, oversized/empty uploads, non-UTF8 byte content).
    mypy (strict on `core/`), `ruff check`/`format`, and
    `scripts/check_dependency_rules.py` all pass; the one new
    `core/services → core/parsers` edge was verified by manual grep to be
    exactly as scoped.
  - New dependency: `defusedxml` (runtime, XXE protection for
    `nmap_parser.py`) + `types-defusedxml` (dev, mypy stubs).
- Threat Intelligence & IOC Extraction Framework
  (`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`) —
  built ahead of the milestone schedule as a new leaf package,
  `core/threat_intel`, peer to `core/parsers`:
  - `models.py`: `IOCType` (twenty types), `ThreatSeverity`,
    `SourceReliability`, `ThreatCategory`, `RuleType`, `IOCRecord`,
    `ThreatScore`, `IOCClassification`, `AttributionRecord`, `ScoredIOC`,
    `NormalizedThreatIntel`, `DetectionRule` (Sigma-adjacent field naming),
    `IOCQuery`/`ProviderLookupResult`/`EnrichmentResult`.
  - `base.py`/`extractor.py`: `BaseIOCExtractor` template method (mirrors
    `BaseParser`) + `IOCExtractionEngine`, one data-driven engine covering
    all twenty `IOCType`s via `patterns.py`'s bounded, ReDoS-safe regex
    table and structured-field extraction — not twenty near-duplicate
    per-type extractor classes.
  - `registry.py`/`provider_registry.py`: plugin-capable `ExtractorRegistry`
    (`cdc.threat_intel_extractors` entry-point group) and an empty,
    plugin-capable `ProviderRegistry` (`cdc.threat_intel_providers`).
  - `validator.py`/`normalizer.py`/`dedup.py`: per-`IOCType` validation
    (`ipaddress`, RFC-shaped regex, hash-length checks, port range, ...),
    canonicalization, and within-run deduplication (never cross-case
    correlation — explicit scope cut).
  - `rules.py`/`rule_validation.py`: `DetectionRuleEngine` (pattern/regex/
    threshold/composite rules, priority ordering, enable/disable) with
    catastrophic-backtracking regex-safety validation enforced at
    registration time, not by review.
  - `scoring.py`/`classification.py`/`attribution.py`: configurable
    `ThreatScoringEngine` (confidence/severity/impact/likelihood/evidence
    quality/source reliability/rule matches, weights sum-validated),
    `ConfidenceCalculator`, `ThreatClassificationEngine`
    (benign/suspicious/malicious/unknown, no MITRE mapping), and
    `EvidenceAttributionTracker` (ties every IOC back to its evidence
    artifact and line numbers).
  - `interfaces.py`: `ThreatIntelProvider`/`IOCEnrichmentProvider`
    `typing.Protocol`s only — no MISP/AlienVault OTX/VirusTotal/AbuseIPDB/
    GreyNoise/OpenCTI implementation, per explicit scope.
  - `metrics.py`/`events.py`/`audit.py`: self-contained observability
    (never imports `core/graph`), mirroring `core/parsers`'s pattern.
  - `core/db/models/ioc.py` (new domain table, `IOC` + `IOCStatus`):
    `evidence_id` a **real** foreign key to `evidence.id` (unlike
    `Evidence.case_id`, that table already exists); `case_id` a plain UUID
    column pending Milestone M1's `Case` model, following the same
    ADR-0011 precedent. Plus `core/db/ioc_repository.py` and its Alembic
    migration (generated, hand-reviewed, and verified against a throwaway
    SQLite DB — table + all seven indexes + the FK constraint confirmed).
  - `core/services/threat_intel_service.py`: `IOCExtractionPipeline`, the
    nine explicit stages (discover → validate → normalize → deduplicate →
    classify → score → persist → publish_event → notify_memory) +
    `extract_threat_intelligence()` orchestrator. `core/services` importing
    `core/threat_intel`/`core/parsers`/`core/memory` directly is a second,
    separately-scoped documented exception (`docs/dependency-rules.md` rule
    4b) to the "services only call `core/graph`" rule.
  - New `Settings` fields (`threat_intel_max_iocs_per_artifact`,
    `threat_intel_max_regex_input_chars`, `threat_intel_min_confidence`,
    `threat_intel_malicious_score_threshold`,
    `threat_intel_suspicious_score_threshold`,
    `threat_intel_enabled_providers`, `threat_intel_provider_timeout_seconds`,
    and one API-key/base-URL pair per named provider), all documented in
    `.env.example`.
  - Two new mermaid diagrams (`docs/diagrams/threat-intel-pipeline.mmd`,
    `ioc-lifecycle.mmd`).
  - No MITRE ATT&CK mapping, no incident/cross-case correlation, no LLM
    reasoning, no concrete threat-intel provider, and no `/api/v1` route —
    all explicit scope cuts per the ADR.
  - 165 new tests (517 total: 500 unit + 17 integration), including a
    regex-catastrophic-backtracking timing regression guard (every one of
    the twenty `IOC_PATTERNS` scanned against a 5,000+ character
    adversarial input in well under a second), rejected-candidate/never-
    silently-dropped assertions, the memory-advisory-failure assertion, and
    a 3,000-line large-evidence-artifact performance test. mypy (strict on
    `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py`
    all pass; the new `core/threat_intel` leaf boundary and the
    `core/services → core/threat_intel`/`core/parsers` edge were verified
    by manual `grep` to be exactly as scoped.

- Finding & MITRE ATT&CK Intelligence Engine
  (`docs/adr/0013-finding-mitre-intelligence-engine-shape.md`) — deterministic
  mapping of scored IOCs to ATT&CK techniques and generation of typed,
  confidence-scored `Finding`s. No LLM reasoning, no investigation logic, no
  cross-case correlation, per explicit scope.
  - `data/mitre/raw/attack-enterprise-15.1.json`: a curated, hand-authored
    STIX 2.1 bundle subset (14 real tactics, 20 real techniques, 5 real
    software entries, 5 real groups, 6 real mitigations, ~39 real
    `uses`/`mitigates` relationships) — vendored, never fetched over the
    network. `data/mitre/README.md` documents provenance and the versioned
    import path for a future/complete official bundle.
  - `core/knowledge/mitre/`: fulfills ADR-0010's deferred
    `KnowledgeSourceType.MITRE_ATTACK` slot. `models.py` (`MitreTactic`/
    `MitreTechnique`/`MitreSoftware`/`MitreGroup`/`MitreMitigation`/
    `MitreRelationship`/`MitreDataset`, versioned via `attack_spec_version`),
    `loader.py` (STIX bundle parsing — local files only, degrades
    malformed-but-known objects to a skipped, logged entry rather than
    aborting the load), `source.py` (`MitreAttackSource`, a concrete
    `KnowledgeSource`), `lookup.py` (`MitreLookup`: fast technique/tactic/
    software/group/mitigation lookups), `bootstrap.py` (`load_mitre_dataset`,
    validates the vendored bundle's version against `Settings.
    mitre_attack_version`).
  - `core/findings/` (new leaf package, peer to `core/threat_intel`): `models.py`
    (`FindingSeverity`/`FindingStatus`/`FindingPriority`/`MitreMapping`/
    `EvidenceBundle`/`FindingConfidence`/`DuplicateMatchResult`/
    `FindingRecord`), `base.py` (`BaseFindingGenerator`, mirrors
    `BaseIOCExtractor`), `mapping_rules.py` (`MAPPING_RULES`: twenty
    data-driven rules covering every vendored technique, supporting both
    one-IOC-to-many-techniques and many-IOCs-to-one-technique via
    co-occurrence boosting), `mapping_engine.py` (`MitreMappingEngine`, the
    one concrete rule-dispatching mapper — validates every rule's
    `technique_id` against the loaded dataset at construction time, never
    mid-evaluation), `evidence_aggregation.py` (`EvidenceAggregator`:
    cross-reference tracking, timeline reconstruction, chain-of-custody
    preservation), `confidence_engine.py` (`ConfidenceEngine`/
    `FindingConfidenceWeights`, all seven required dimensions, weights
    sum-validated), `severity.py` (pure `assign_severity`/`assign_priority`/
    `calculate_risk_score` functions), `dedup.py`
    (`FindingDeduplicationEngine`: six required dimensions — hash/IOC/
    technique/evidence/time-window/host overlap — bucket-first and
    technique-overlap-gated to avoid both O(n²) blow-up and false merges
    across disjoint technique hypotheses; `merge_findings()`),
    `finding_generator.py` (`FindingGenerationEngine`, one candidate Finding
    per mapped technique), `metrics.py`/`events.py`/`audit.py`
    (self-contained observability; `events.py` defines the six required
    lifecycle events: `FindingCreated`/`FindingUpdated`/`FindingMerged`/
    `TechniqueMapped`/`ConfidenceUpdated`/`FindingClosed`).
  - `core/db/models/{mitre_tactic,mitre_technique,mitre_software,mitre_group,
    mitre_mitigation}.py`: five reference tables, each with a surrogate UUID
    PK, a unique indexed business column + `attack_spec_version` (append-only
    versioning — never an in-place mutation), seeded only by
    `scripts/mitre/import_attack_bundle.py`. `core/db/models/finding.py`
    (`Finding` + `FindingStatus`; `case_id` a plain UUID column pending
    Milestone M1's `Case` model, following the `Evidence.case_id`/
    `IOC.case_id` precedent; `primary_evidence_id`/`primary_ioc_id` real
    nullable FKs) and `core/db/models/finding_mitre_mapping.py`
    (`FindingMitreMapping`, the real many-to-many join table). Plus
    `core/db/finding_repository.py` and `core/db/mitre_repository.py`, and
    two hand-reviewed Alembic migrations (generated via
    `alembic revision --autogenerate`, verified end-to-end against a
    throwaway SQLite DB — all tables, indexes, unique constraints, and FKs
    confirmed present).
  - `core/services/finding_service.py`: `FindingGenerationPipeline`, the
    explicit stages (discover → map_and_generate → deduplicate → persist →
    publish_event → notify_memory) + `generate_findings_for_case()`
    orchestrator. `core/services` importing `core/findings`/
    `core/threat_intel` (models only)/`core/knowledge`/`core/memory` directly
    is a third, separately-scoped documented exception
    (`docs/dependency-rules.md` rule 4c).
  - `scripts/mitre/import_attack_bundle.py`: the only supported way ATT&CK
    data enters the system — idempotent, offline-only, seeds all five
    reference tables from a local vendored bundle.
  - New `Settings` fields (`mitre_attack_data_path`, `mitre_attack_version`,
    `finding_mapping_min_confidence`, `finding_dedup_similarity_threshold`,
    `finding_dedup_time_window_minutes`, `finding_max_candidates_per_case`),
    documented in `.env.example`.
  - Two new mermaid diagrams (`docs/diagrams/finding-mitre-mapping-pipeline.mmd`,
    `finding-lifecycle.mmd`).
  - 112 new tests (629 total), including a real-vendored-bundle consistency
    test (every shipped `MAPPING_RULES` entry resolves against the real
    20-technique dataset), an idempotent-import regression test, a
    missing-technique-seed degradation test (never crashes, logs and skips
    the join row), and two performance guards (300 and 500 mixed-type IOCs
    generating/deduplicating/persisting well under the time budget). mypy
    (strict on `core/`), `ruff check`/`format`, and
    `scripts/check_dependency_rules.py` all pass; the new `core/findings`/
    `core/knowledge/mitre` leaf boundaries and the
    `core/services → core/findings`/`core/knowledge`/`core/threat_intel`
    edge were verified by manual `grep` to be exactly as scoped.

### Fixed
- Re-verification pass over the Evidence Ingestion & Parser Framework
  (`core/parsers/`): confirmed `ruff check`/`format`, `mypy --strict`,
  `pytest` (517 tests), and `scripts/check_dependency_rules.py` all pass
  with no code changes needed — no deviation from
  `context/01_blueprint.md`/`context/03_engineering_constitution.md` found.
- `mypy core --strict` gap closed (6 `[type-arg]` errors, none in
  `core/parsers`): `core/tools/registry.py`'s `ToolRegistry` and
  `core/agents/base.py`'s `BaseAgent.use_tool` now type tool instances as
  `BaseTool[Any, Any]` instead of the bare generic (a registry holds
  heterogeneous tool input/output types by design); `core/graph/
  workflow_engine.py`'s `WorkflowEngine` now fully parameterizes
  `StateGraph`/`CompiledStateGraph` as `[CaseInvestigationState, Any, Any,
  Any]` (LangGraph's four type parameters: `StateT, ContextT, InputT,
  OutputT`). Typing-only; no behavioral change.

<!--
Template for future entries:

## [v0.X-milestone-name] - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...
-->
