# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Still no concrete specialist agent, `Case` model, or investigation logic exists.** What is now complete, beyond the M0 engineering foundation, the M3 Multi-Agent Framework, the M6 Memory & Knowledge Layer, and the M1 Evidence Ingestion & Parser Framework, is the **Threat Intelligence & IOC Extraction Framework**: a reusable, agent-independent pipeline that transforms `core.parsers.models.NormalizedEvidence` into structured, scored, classified threat intelligence, plus the second real domain table (`IOC`) and its persistence. Built ahead of the milestone schedule (normally part of M4, alongside the Threat Hunting Agent) at explicit user direction — framework-first, extending the exact precedent set by the Multi-Agent Framework (ADR-0009), Memory & Knowledge Layer (ADR-0010), and Evidence Ingestion & Parser Framework (ADR-0011) sessions. Full design rationale, including four deliberate architecture extensions and several planning-stage refinements: `docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`.

### M0 foundation + Multi-Agent Framework + Memory & Knowledge Layer + Evidence Ingestion Framework (unchanged from prior sessions)

- **Configuration, logging, shared contracts, DB foundation, FastAPI app, governance, `core/agents`/`core/tools`/`core/graph` framework, `core/memory`/`core/knowledge` framework, `core/parsers` framework (9 parsers) + `Evidence` domain table + `core/services/evidence_service.py`** — unchanged, see prior sessions' detail in git history / `docs/adr/0001-0011`.

### Threat Intelligence & IOC Extraction Framework (new this session)

- **`core/threat_intel/models.py`** — the canonical IOC/threat-intel contracts: `IOCType` (twenty types: IPv4/IPv6, domain, hostname, URL, email, SHA1/SHA256/MD5, file name, username, process name, registry key, port, service, mutex, scheduled task, command line, user agent, certificate fingerprint), `ThreatSeverity`, `SourceReliability`, `ThreatCategory`, `RuleType`/`ThresholdOperator`/`CompositeOperator`, `IOCRecord` (one candidate/extracted indicator), `RuleMatchResult`, `ThreatScore` (all seven scoring dimensions), `IOCClassification`, `AttributionRecord`, `ScoredIOC` (the fully-processed record), `NormalizedThreatIntel` (the per-artifact container, mirroring `NormalizedEvidence`), `DetectionRule` (Sigma-adjacent field naming for future compatibility), `IOCQuery`/`ProviderLookupResult`/`EnrichmentResult` (provider-interface payloads).
- **`core/threat_intel/base.py`** — `BaseIOCExtractor`, a template-method base shaped identically to `BaseParser`: `__call__` owns timing, metrics, structured logging, and the constitution §1.7 contract (never crash — an oversized/malformed artifact degrades to whatever candidates were found before the failure, logged, never silently total data loss).
- **`core/threat_intel/patterns.py`** — twenty bounded, ReDoS-safe regex patterns (`IOC_PATTERNS`, no nested/overlapping quantifiers, verified by a dedicated timing regression test against 5,000+ character adversarial input) plus `refang()` (reverses `hxxp://`/`[.]`/`(dot)`/etc. defanging conventions before scanning) and `STRUCTURED_FIELD_SOURCES` (higher-confidence extraction straight from a parser's structured `ip_address`/`host`/`user` fields). `IOCType.HOSTNAME` deliberately has **no** free-text pattern — a bare alphanumeric token matches almost any English word, so hostnames are extracted only from the structured field, never guessed from raw text.
- **`core/threat_intel/extractor.py`** — `IOCExtractionEngine(BaseIOCExtractor)`, the one concrete, data-driven extractor dispatching every `IOCType` from `patterns.py` rather than twenty near-duplicate per-type classes (ADR-0012's central design decision). Enforces a whole-artifact character cap (`Settings.threat_intel_max_regex_input_chars`) before scanning.
- **`core/threat_intel/registry.py`** — `ExtractorRegistry`, plugin-capable exactly like `ParserRegistry` (aliases, priority, enable/disable, `importlib.metadata` entry-point discovery under the `cdc.threat_intel_extractors` group). `default_extractor_registry()` auto-registers `IOCExtractionEngine` then calls `load_plugins()`.
- **`core/threat_intel/validator.py`** — `IOCValidator`, per-`IOCType` structural validation (`ipaddress` for IPv4/IPv6, RFC-shaped regex for domain/email, exact hex-length checks for MD5/SHA1/SHA256, `1-65535` port range, etc.), raising `IOCValidationError`.
- **`core/threat_intel/normalizer.py`** — `IOCNormalizer`, per-`IOCType` canonicalization (IP compression, domain/email/hash lowercasing, command-line whitespace collapsing) — deterministic, `raw_value` always preserved unchanged.
- **`core/threat_intel/dedup.py`** — `deduplicate_iocs()`, merges candidates sharing `(ioc_type, value)` within one extraction run (never cross-case — explicit scope cut), keeping the earliest `first_seen`, the highest `confidence`, and accumulating tags/line-numbers rather than dropping data.
- **`core/threat_intel/rule_validation.py`** + **`rules.py`** — `DetectionRuleEngine`: pattern/regex/threshold/composite rule types, priority ordering, enable/disable, and `validate_regex_safety()` (length cap + nested-quantifier heuristic + compile check) enforced at *registration* time, never discovered mid-evaluation — the "protect against catastrophic regex" requirement met structurally, not by review.
- **`core/threat_intel/scoring.py`** — `ThreatScoringEngine` (all seven required dimensions: confidence/severity/impact/likelihood/evidence-quality/source-reliability/rule-matches, folded via a configurable, sum-to-1.0-validated `ScoringWeights`) + `ConfidenceCalculator` (a separate, smaller deterministic combination).
- **`core/threat_intel/classification.py`** — `ThreatClassificationEngine`: configurable score thresholds map to `benign`/`suspicious`/`malicious`/`unknown` (never a MITRE technique — explicit scope cut); a matched detection rule always at least elevates a candidate to `suspicious`.
- **`core/threat_intel/attribution.py`** — `EvidenceAttributionTracker`: ties every IOC back to its evidence artifact and observed line number(s) — the explainability trail.
- **`core/threat_intel/interfaces.py`** + **`provider_registry.py`** — `ThreatIntelProvider`/`IOCEnrichmentProvider` `typing.Protocol`s (mirroring `core.knowledge.interfaces`'s "structural contract, zero implementation" pattern) and an empty, plugin-capable `ProviderRegistry` (`cdc.threat_intel_providers` entry-point group). **No concrete MISP/AlienVault OTX/VirusTotal/AbuseIPDB/GreyNoise/OpenCTI provider exists** — interfaces only, per explicit instruction.
- **`core/threat_intel/metrics.py`**, **`events.py`**, **`audit.py`** — self-contained, leaf-layer observability (never import `core.graph.events.EventBus`), mirroring `core/parsers`'s identical pattern.
- **`core/db/models/ioc.py`** (extends the `core/db/models/` package) — `IOC(Entity)` + `IOCStatus`. `evidence_id` is a **real foreign key** to `evidence.id` (unlike `Evidence.case_id`, that table already exists); `case_id` is a plain UUID column pending Milestone M1's `Case` model, following the exact `Evidence.case_id` precedent. Seven indexes (case_id, evidence_id, ioc_type, value, severity, classification, status). `core/db/models/__init__.py` updated; the migration `d1d941bb0216_create_ioc_table.py` is generated, hand-reviewed, and verified (applied to a throwaway SQLite DB — table, all seven indexes, and the FK constraint confirmed present).
- **`core/db/ioc_repository.py`** — `IOCRepository(BaseRepository[IOC])` + `find_by_case`, `find_by_evidence`, `find_by_value_and_type` (dedup/correlation-primitive lookup), `find_by_type`, `mark_dismissed`, `mark_false_positive`, `increment_occurrence`.
- **`core/services/threat_intel_service.py`** — `IOCExtractionPipeline`, the nine explicit pipeline stages requested — `discover` → `validate` → `normalize` → `deduplicate` → `classify` → `score` → `persist` → `publish_event` → `notify_memory` — composed by one `extract_threat_intelligence()` orchestrator, plus `get_ioc()`/`list_iocs_for_case()`. `notify_memory` is advisory-only (a broken `CaseMemory` never breaks extraction, verified by test).
- **New `Settings` fields**: `threat_intel_max_iocs_per_artifact`, `threat_intel_max_regex_input_chars`, `threat_intel_min_confidence`, `threat_intel_malicious_score_threshold`, `threat_intel_suspicious_score_threshold`, `threat_intel_enabled_providers` (+ derived `_list` property), `threat_intel_provider_timeout_seconds`, and one API-key/base-URL pair per named provider (MISP, AlienVault OTX, VirusTotal, AbuseIPDB, GreyNoise, OpenCTI) — all documented in `.env.example`.
- **New mermaid diagrams**: `docs/diagrams/threat-intel-pipeline.mmd` (the nine-stage sequence), `ioc-lifecycle.mmd` (one candidate IOC's state machine, discovery through persistence, including the never-silently-drop-a-rejection path).
- **Testing** — 165 new tests (517 total, up from 352): one dedicated `tests/unit/test_threat_intel_*.py` file per framework module (20 files), `test_db_ioc_repository.py` (real SQLite, mirroring `test_db_evidence_repository.py`'s pattern), `test_threat_intel_service.py` (full pipeline, including a rejected-candidate assertion, the memory-advisory-failure assertion, a detection-rule-match classification test, and a 3,000-line large-evidence-artifact performance test). A dedicated `test_threat_intel_patterns.py::test_every_pattern_compiles_and_matches_bounded_text_quickly` regression-guards every one of the twenty patterns against catastrophic backtracking. mypy (strict on `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py` all pass; the new `core/threat_intel` leaf boundary and the `core/services → core/threat_intel`/`core/parsers` edge were verified by manual `grep` to be exactly as scoped in the ADR.
- **No new runtime dependency** — `core/threat_intel` uses only the stdlib (`re`, `ipaddress`, `urllib.parse`, `importlib.metadata`).

**Explicitly NOT built, by this session's stated scope:** `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` domain models, any concrete specialist agent (SOC Analyst, Threat Hunting, Phishing, Vulnerability, OWASP, Linux Security, Incident Response, MITRE Mapping), MITRE ATT&CK mapping of any kind, incident/cross-case correlation (only the `find_by_value_and_type` lookup primitive a future correlation feature could build on), any LLM reasoning, any concrete `ThreatIntelProvider`/`IOCEnrichmentProvider` implementation, any `/api/v1` route, `email_parser.py`/`nessus_parser.py`/`openvas_parser.py`/`source_code_parser.py`/`incident_parser.py`, `core/security/*`, `core/reporting/*`, any `apps/web` code.

---

## Repository Status

```
apps/
  api/            FastAPI app (unchanged)                          [implemented]
  web/             Streamlit frontend                               [README only]
core/
  config/         settings.py + evidence_*/threat_intel_* fields    [implemented]
  logging/        (unchanged)                                       [implemented]
  exceptions.py, schemas.py, interfaces.py                          [implemented]
  agents/         (unchanged — framework only)                      [implemented — framework only]
  tools/          (unchanged — framework only)                      [implemented — framework only]
  memory/         (unchanged — framework only)                      [implemented — framework only]
  knowledge/      (unchanged — abstraction + one retriever)          [implemented — abstraction only]
  graph/          (unchanged — framework only)                       [implemented — framework only]
  db/             base_repository.py, session.py (unchanged) +
                   models/ (__init__.py, evidence.py, ioc.py NEW),
                   evidence_repository.py, ioc_repository.py (NEW),
                   migrations/versions/ (+ d1d941bb0216_create_ioc_table.py NEW) [implemented — 2 domain tables]
  parsers/        (unchanged — 9 parsers + framework)                [implemented — 9 parsers + framework]
  threat_intel/   models.py, exceptions.py, base.py, patterns.py,
                   extractor.py, registry.py, validator.py,
                   normalizer.py, dedup.py, rule_validation.py,
                   rules.py, scoring.py, classification.py,
                   attribution.py, interfaces.py, provider_registry.py,
                   metrics.py, events.py, audit.py                   [NEW — implemented, 20 modules]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       evidence_service.py, threat_intel_service.py (NEW);
                   case_service.py, report_service.py                [implemented — evidence + threat intel]
data/
  sample_evidence/ (unchanged — 9 fixtures + malformed/)             [unchanged]
tests/
  unit/           83 test modules (500 tests total, +148 modules/+165 tests this session)
  integration/    4 test modules (17 tests, unchanged)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (13 ADR files incl. template) +
                   docs/diagrams/ (+2 new .mmd files)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          (unchanged)
.github/          (unchanged)
```

517 tests passing as of this session (352 unit + integration prior → 500 unit + 17 integration now). This session added 21 new `core/threat_intel/` modules (20 code + `__init__.py`... actually 20 total incl. `__init__.py`/README), 2 new `core/db/` files + 1 migration, 1 new `core/services/` file, 20 new test files, 1 new ADR, 2 new diagrams, plus edits to `core/config/settings.py`, `.env.example`, `core/db/models/__init__.py`, `docs/dependency-rules.md`, `docs/roadmap.md`, `docs/diagrams/README.md`, `core/db/README.md`, `core/services/README.md`, `CHANGELOG.md`, and this file — all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` and `context/03_constitution.md` still do not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0009/0010/0011 per ADR-0012's explicit scoping. Four deliberate architecture extensions, all documented in `docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`:

1. **`core/threat_intel/` is a new leaf package, peer to `core/parsers`/`core/tools`** — added to `docs/dependency-rules.md`'s layer-stack diagram and rule 5. It may import `core.parsers.models` (the `NormalizedEvidence` input contract only — the same sideways-leaf-model precedent `core/db/models/evidence.py` already set by importing `core.parsers.models.EvidenceType`), `core.config`, `core.logging`, `core.exceptions`; it may never import `core.agents`, `core.graph`, `core.memory`, or `core.db`.
2. **`core/services/threat_intel_service.py` may import `core/threat_intel`, `core/parsers`, and `core/memory` directly** — a new, narrowly-scoped rule 4b in `docs/dependency-rules.md`, the second documented exception to "services only call `core/graph`" (the first being `evidence_service.py`'s rule 4a). IOC extraction is deterministic, pre-investigation processing.
3. **`IOC.evidence_id` is a real foreign key to `evidence.id`; `IOC.case_id` is a plain UUID column, not a foreign key.** Unlike `Evidence.case_id` (ADR-0011, where nothing existed to reference), `evidence` already exists, so the FK is real from the start. `case_id` still has no `Case` table to reference — resolved by the same follow-up migration Milestone M1 already owes `Evidence.case_id`.
4. **Threat Intelligence Provider interfaces are `typing.Protocol` definitions only, with an empty `ProviderRegistry`** — mirrors `core/knowledge/interfaces.py`'s "structural contract, zero implementation" pattern exactly (ADR-0010 precedent, extended here).

Plus all architectural notes carried forward unchanged from prior sessions (see git history for ADR-0001 through 0011's individual points). No approved architectural decision has been reversed. `docs/roadmap.md`'s M4 checkbox remains unchecked — the Threat Intelligence & IOC Extraction Framework is implemented, but M4's own demo criterion (all 9 modules functioning through the Coordinator) needs the concrete Vulnerability/OWASP/Linux/Threat Hunting agents first.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior sessions' "Key Decisions" sections in git history for the full list, e.g. UUID surrogate PKs via `Entity`; `Tool`/`Agent` Protocol variance; ruff format only; cursor pagination by UUID `id`; two-tier error handling; `core/parsers`/`core/memory`/`core/knowledge` own their own persistence; `BaseParser`/`ParserRegistry`'s shape as the template every subsequent framework layer reuses.)*

**New this session:**

- **`core/threat_intel` reuses `core/parsers`'s exact patterns rather than inventing new ones.** `BaseIOCExtractor` is `BaseParser`'s template-method shape applied to a fourth layer; `ExtractorRegistry`/`ProviderRegistry` are `ParserRegistry`'s pattern, applied twice (extraction strategies and external providers respectively); `metrics.py`/`events.py` are `core/parsers/metrics.py`/`events.py`'s "self-contained, no `EventBus`" pattern applied again.
- **One data-driven `IOCExtractionEngine`, not twenty near-duplicate per-type extractor classes.** All twenty `IOCType` patterns and normalizers are dispatched from data tables (`patterns.py`, `normalizer.py`); extensibility for a genuinely novel extraction strategy is still provided by `ExtractorRegistry`'s plugin seam. Documented explicitly in ADR-0012's "Alternatives Considered."
- **`IOCType.HOSTNAME` has no free-text regex pattern**, discovered and fixed during implementation: a bare single-token pattern matches almost any English word, producing pure noise when scanned against arbitrary log text. Hostnames are extracted only from a parser's structured `host` field. A regression test (`test_threat_intel_extractor.py`) and the removal are both documented in `patterns.py`'s own comment.
- **Regex safety is enforced structurally, not by review**, for both the built-in `IOC_PATTERNS` (all twenty are bounded — fixed `{m,n}` quantifiers, no nesting, verified by a timing regression test) and any future user-registered `DetectionRule.regex` (validated at *registration* time via `validate_regex_safety()` — length cap + nested-quantifier heuristic + compile check — never discovered mid-evaluation).
- **Detection rules carry Sigma-adjacent field names from the start** (`rule_id`, `name`≈title, `severity`≈level, `enabled`≈status, `tags`) without depending on a Sigma library or importing real Sigma rules — deferred exactly as far as blueprint §17's existing "Sigma rule engine" future-expansion entry already deferred it.
- **Threat scoring weights are configurable and validated to sum to 1.0** (`ScoringWeights`, a Pydantic model with a `model_validator`) rather than hardcoded — the task's explicit "do not hardcode scoring values" requirement, made structurally enforced (a misconfigured weight set fails at construction, not silently at first use).
- **No FastAPI route this session** — mirrors ADR-0011's identical scope cut; `Case` doesn't exist yet.

---

## Public Interfaces

*(M0/M3/M6/M1-evidence interfaces — `core.config`, `core.logging`, `core.exceptions`, `core.schemas`, `core.interfaces`, `core.db.{Base, BaseRepository, Database, Entity}`, `core.agents.*`, `core.tools.*`, `core.graph.*`, `core.memory.*`, `core.knowledge.*`, `core.parsers.*`, `apps.api.*` — unchanged from prior sessions except as noted below.)*

**Threat intel contracts:** `core.threat_intel.models.{IOCType, ThreatSeverity, SourceReliability, ThreatCategory, RuleType, ThresholdOperator, CompositeOperator, IOCRecord, RuleMatchResult, ThreatScore, IOCClassification, AttributionRecord, ScoredIOC, NormalizedThreatIntel, DetectionRule, IOCQuery, ProviderLookupResult, EnrichmentResult}`, `core.threat_intel.base.{BaseIOCExtractor, ExtractorRunResult}`, `core.threat_intel.exceptions.{ThreatIntelError, UnknownIOCTypeError, MalformedIOCError, IOCValidationError, UnsafeRegexError, OversizedEvidenceError, RuleValidationError, ProviderUnavailableError, ProviderRateLimitedError}`.

**Threat intel framework:** `core.threat_intel.patterns.{IOC_PATTERNS, STRUCTURED_FIELD_SOURCES, refang}`, `core.threat_intel.extractor.IOCExtractionEngine`, `core.threat_intel.registry.{ExtractorRegistry, default_extractor_registry, PLUGIN_ENTRY_POINT_GROUP}`, `core.threat_intel.validator.IOCValidator`, `core.threat_intel.normalizer.IOCNormalizer`, `core.threat_intel.dedup.deduplicate_iocs`, `core.threat_intel.rule_validation.{validate_regex_safety, validate_rule_shape}`, `core.threat_intel.rules.DetectionRuleEngine`, `core.threat_intel.scoring.{ScoringWeights, ConfidenceCalculator, ThreatScoringEngine}`, `core.threat_intel.classification.ThreatClassificationEngine`, `core.threat_intel.attribution.EvidenceAttributionTracker`, `core.threat_intel.interfaces.{ThreatIntelProvider, IOCEnrichmentProvider}`, `core.threat_intel.provider_registry.{ProviderRegistry, default_provider_registry, MISP, ALIENVAULT_OTX, VIRUSTOTAL, ABUSEIPDB, GREYNOISE, OPENCTI}`, `core.threat_intel.metrics.ThreatIntelMetricsCollector`, `core.threat_intel.events.{ThreatIntelEvent, ThreatIntelEventType, ThreatIntelEventPublisher}`, `core.threat_intel.audit.{AuditAction, log_threat_intel_audit_event}`.

**Domain persistence:** `core.db.models.{Evidence, EvidenceStatus, IOC, IOCStatus}`, `core.db.evidence_repository.EvidenceRepository`, `core.db.ioc_repository.IOCRepository`.

**Threat intel service:** `core.services.threat_intel_service.{IOCExtractionPipeline, extract_threat_intelligence, get_ioc, list_iocs_for_case, ThreatIntelExtractionResult, DEGRADED_SCORE_THRESHOLD}`.

No `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` models/schemas, concrete specialist agents, concrete `ThreatIntelProvider`/`IOCEnrichmentProvider` implementations, or `/api/v1` routes exist as public interfaces yet.

---

## Remaining Work

Unchanged in substance from the prior session's plan (see `docs/roadmap.md`), except M4's IOC-extraction piece is now done ahead of schedule:

1. **M1 — remaining piece.** `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` domain models + their Alembic migration (including follow-up migrations turning `Evidence.case_id` and `IOC.case_id` into real FKs); `core/tools/scoring.py`; `core/agents/soc_analyst_agent.py`; first real `/api/v1` route wiring `evidence_service`/`case_service` together.
2. **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE Agent; Phishing Investigation Agent + `email_parser.py` + `core/security/prompt_guard.py`.
3. **M3 — remaining piece:** wire real agents through the now-implemented framework.
4. **M4 — remaining piece.** Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent, Linux Security Agent, and — now that the extraction framework exists — `core/agents/threat_hunter_agent.py`, which calls `core.services.threat_intel_service.extract_threat_intelligence()` and reasons over its typed output (the same "framework built, agent still unbuilt" pattern ADR-0011 established for `parser_agent.py`).
5. **M5 — Incident Response synthesis + Reporting.**
6. **M6 — remaining piece:** swap `InMemoryVectorStore` for real ChromaDB, populate knowledge data, Threat Timeline/MITRE heatmap/AI Analyst Chat UI.
7. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md`/`03_constitution.md` don't exist; `make migrate`/`make seed` are no-ops; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no performance/load testing beyond the one 3,000-line threat-intel pipeline timing assertion; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix — this session's `core/threat_intel` boundary and `core/services → core/threat_intel`/`core/parsers` edge were verified manually via `grep`; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is not semantic; numpy not installed; `windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`.)*

- **`Evidence.case_id` and `IOC.case_id` have no referential integrity yet** (plain UUID, no FK) — resolved when Milestone M1 adds `Case` and its follow-up FK migration for both tables.
- **No `/api/v1` route exists for threat intel** — `extract_threat_intelligence()` is only callable from `core/services` directly, not yet from `apps/api` or `apps/web`.
- **The Detection Rule Engine's regex-safety check is a heuristic, not a full NFA analysis** — `validate_regex_safety()`'s nested-quantifier pattern catches the classic catastrophic-backtracking shapes but is not a formal proof of linear-time matching; paired with a runtime input-length cap as defense in depth, documented explicitly in `rule_validation.py`'s docstring.
- **`IOC_PATTERNS`'s free-text scanning is inherently precision-limited** (e.g. the `FILE_NAME`/`USERNAME`/`COMMAND_LINE` patterns can over-match on ordinary log text) — mitigated by per-type `IOCValidator` rejection and low default `pattern_scan` confidence (0.6) versus structured-field extraction (0.95), but not eliminated; a known, inherent limitation of regex-only extraction without an LLM-assisted fallback (out of scope this session).

---

## Dependencies

Runtime (`requirements.txt`): **no new dependency this session** — `core/threat_intel` uses only the stdlib (`re`, `ipaddress`, `urllib.parse`, `importlib.metadata`).

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`), with two prior commits: `8664039 feat(parsers): implement Evidence Ingestion & Parser Framework ahead of schedule` (which followed `0ee65d5` and `eae4fb8`). This session's Threat Intelligence & IOC Extraction Framework work is **uncommitted**:

- Modified: `CHANGELOG.md`, `context/current_state.md`, `docs/roadmap.md`, `docs/dependency-rules.md`, `docs/diagrams/README.md`, `core/db/README.md`, `core/services/README.md`, `core/config/settings.py`, `core/db/models/__init__.py`, `.env.example`.
- Untracked (new): `docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`, `docs/diagrams/{threat-intel-pipeline,ioc-lifecycle}.mmd`, all 20 new `core/threat_intel/*.py` modules + `README.md`, `core/db/models/ioc.py`, `core/db/ioc_repository.py`, `core/db/migrations/versions/d1d941bb0216_create_ioc_table.py`, `core/services/threat_intel_service.py`, and 20 new `tests/unit/test_{threat_intel,db_ioc}_*.py` files.

The working tree is in a complete, self-consistent, fully-tested state (517 tests passing — mypy/ruff/dependency-rules clean, migration verified against a real SQLite DB) but has not yet been committed; commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement the remaining piece of Milestone M1 exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: add `core/db/models/case.py` (and `finding.py`, `mitre_technique.py`, `timeline_event.py`, `report.py`) defining `Case`, `Finding`, `MitreTechnique`, `TimelineEvent`, and `Report` (each inheriting `core.db.Entity`, per `context/01_blueprint.md` §8 and `context/03_engineering_constitution.md` §7), generate the Alembic migration against them (including follow-up migrations that turn both `Evidence.case_id` and `IOC.case_id` into real foreign keys against the new `Case` table — additive, per constitution §7), implement `core/tools/scoring.py` as a concrete `BaseTool` subclass, and implement `core/agents/soc_analyst_agent.py` as a concrete `BaseAgent` subclass — constructed with a real `core.memory.case_memory.SQLiteCaseMemory` rather than `None` — registered into `AgentRegistry` and wired into `core/graph/investigation_graph.py`. Wire `core.services.evidence_service.ingest_evidence()`, `core.services.threat_intel_service.extract_threat_intelligence()`, and a new `core.services.case_service` together, and add the first real `/api/v1` routes (`apps/api/routers/cases.py`, `evidence.py`, and/or `iocs.py`) so a case can actually be created, have evidence uploaded, and have IOCs extracted end-to-end. Do not build the OWASP/Vulnerability/Phishing/Threat-Hunting agents yet, and do not populate any MITRE/OWASP knowledge data yet — those are later milestones. Preserve every existing file and architectural decision described in this document, including the Multi-Agent Framework, the Memory & Knowledge Layer, the Evidence Ingestion & Parser Framework, and the Threat Intelligence & IOC Extraction Framework built in prior sessions; only extend them.
