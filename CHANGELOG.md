# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once
`v1.0.0` is tagged. Pre-1.0 releases are tagged per milestone
(`v0.1-foundation`, `v0.2-single-agent`, ...) as described in
`docs/roadmap.md`.

## [Unreleased]

### Added
- **AI Investigation Assistant / Conversational Interface**
  (`docs/adr/0025-ai-investigation-assistant-conversational-interface.md`) —
  blueprint §13's AI Analyst Chat: free-form, case-scoped Q&A grounded in
  already-persisted case evidence, never a generic chatbot. New leaf
  package `core/conversation/` — `models.py` (`ConversationRetrievalContext`,
  `RetrievedItem`, `SourceReference`, `ToolSelection`,
  `AssembledConversationContext`, `PromptPayload`, `ChatCompletion`,
  `ConversationAnswer`, `ConversationSession`, `ConversationAuditEvent`),
  `retrieval.py` (`RetrievalLayer` — deterministic keyword-relevance
  scoring over Findings/IOCs/MITRE mappings/Reports/Timeline events),
  `tool_selection.py` (`ToolSelectionEngine` — deterministic keyword
  routing to retrieval categories), `context_builder.py`
  (`ConversationContextBuilder` — rank + budget-truncate), `prompt_builder.py`
  (`PromptBuilder`), `llm_provider.py` (`ChatModelProvider` — blueprint §5's
  "pluggable `ModelProvider` interface," first defined here — plus
  `TemplateChatModelProvider`, a deterministic, non-generative default
  implementation; no external OpenAI/Gemini/Ollama client integrated this
  session, per explicit task scope), `response_orchestrator.py`
  (`ResponseOrchestrator`), `citation_engine.py` (`CitationEngine` — never
  fabricates a citation for a source that wasn't actually retrieved),
  `session_manager.py` (`SessionManager` — process-local chat-session
  metadata), `conversation_manager.py` (`ConversationManager` — the pipeline
  orchestrator), `audit.py`/`metrics.py`. Reuses (never duplicates)
  `core.memory.conversation_memory.ConversationMemory` for chat turn
  storage, per ADR-0010's existing scope. New `core/services/
  conversation_service.py` (`ask_question`) hydrates case data from
  `Finding`/`IOC`/`Report`/`TimelineEvent` repositories, screens the
  question through `core.security.prompt_guard` (a new, documented
  dependency-rules.md exception, rule 4j), and never triggers a new
  investigation run — read-only over what the pipeline already produced.
  New `POST /api/v1/cases/{case_id}/conversation` route. No frontend chat
  UI, no streaming, no new authentication (explicit task scope) — 51 new
  tests (1704 total, up from 1653).
- **Report Generator Agent** (`docs/adr/0024-report-generator-agent.md`) —
  blueprint §7's Report Generator, the tenth concrete specialist agent
  (**closes M5 entirely** — the Incident Response Agent half was already
  done). New leaf package `core/reporting/` (deterministic report-assembly
  pipeline: `section_builders.py` — one pure function per task-named
  section (Executive Summary, Case Overview, Investigation Timeline,
  Evidence Summary, IOC Summary, Threat Intelligence Summary, MITRE
  Mapping, Findings, Incident Response Actions, Risk Assessment,
  Recommendations, Appendix); `section_registry.py` — which sections each
  of the eight task-named report types includes (Executive Summary,
  Technical Investigation, Incident Response, IOC Summary, MITRE ATT&CK,
  Timeline, Threat Intelligence, Evidence); `completeness_validator.py`,
  `statistics_calculator.py`, `confidence_calculator.py`,
  `report_engine.py` (`ReportGenerationEngine` — generate sections ->
  assemble -> validate -> calculate statistics -> build `GeneratedReport`),
  `metrics.py`/`audit.py`) with typed models (`GeneratedReport`,
  `ReportSection`, `ReportStatistics`, `ReportValidationResult`,
  `ReportType`, `ReportFormat`, `ReportSectionType`). `core/tools/
  report_tools.py` (blueprint's exact named file, `ReportGenerationTool`)
  wraps `core.reporting.report_engine.ReportGenerationEngine`, mirroring
  `ir_tools.py`'s shape — a new documented dependency-rules.md exception
  (rule 5c) lets this one tool file import `core/reporting` directly.
  `core/agents/report_generator_agent.py` (`ReportGeneratorAgent`,
  capability `report_generation`) never computes a severity, risk score,
  MITRE mapping, or confidence itself — it normalizes this case's
  already-persisted `Finding`/MITRE-mapping records, this upload's
  already-hydrated specialist records, and the case's most recently
  *persisted* `IncidentResponsePlan` (new `CaseInvestigationState.
  incident_response_plan_record`, hydrated by
  `case_service._hydrate_incident_response_plan_record`) into a
  `ReportGenerationContext` and calls its one tool. Cross-cutting, not
  evidence-type-gated, mirroring `MitreMappingAgent`/`IncidentResponseAgent`'s
  routing — auto-regenerates a Technical Investigation Report on every
  evidence upload. **Real DB persistence** — the placeholder `reports`
  table (blueprint §8's literal `Case -> 1 Report (nullable)`) is extended
  additively with `title`/`report_data_json`/`overall_confidence`/`degraded`
  columns and six new `report_type_enum` values, upserted via
  `ReportRepository.upsert_for_case` (one row per case, replaced not
  appended, mirroring `IncidentResponsePlanRepository`). Deliberately
  **not** built this session, per explicit task instruction ("implement
  only the backend models and generation pipeline... do not build exporters
  yet"): `core/reporting/{templates,charts.py,pdf_builder.py}` (Jinja2/
  Plotly/ReportLab) and an on-demand `/api/v1/cases/{case_id}/reports`
  route to request one of the other seven report types directly.
- **Incident Response Agent** (`docs/adr/0023-incident-response-agent.md`)
  — blueprint §7's downstream, cross-agent synthesizer, the ninth concrete
  specialist agent. New leaf package `core/incident_response/` (deterministic,
  NIST SP 800-61-aligned response-plan synthesis: `IncidentSeverityClassifier`,
  a MITRE-tactic/keyword/severity-fallback playbook rule engine,
  `RiskPrioritizer`, `order_recommendations` dedup+ordering,
  plan-level confidence/risk rollups, metrics, audit) with typed models
  (`IncidentResponsePlan`, `ResponseAction`, `ResponseRecommendation`,
  `ResponsePriority`, `ResponseCategory`, `ResponsePhase`, `ResponseEvidence`,
  `ResponseMetrics`). `core/tools/ir_tools.py` (blueprint's exact named file,
  `IncidentResponsePlanGenerationTool`) wraps
  `core.incident_response.response_plan_engine.ResponsePlanEngine`, mirroring
  `mitre_tools.py`'s shape — a new documented dependency-rules.md exception
  (rule 5b) lets this one tool file import `core/incident_response` directly.
  `core/agents/incident_response_agent.py` (`IncidentResponseAgent`,
  capability `incident_response_synthesis`) never computes a severity, risk
  score, MITRE mapping, or recommendation itself — it normalizes this case's
  already-persisted `Finding` rows (new `CaseInvestigationState.
  incident_response_finding_records`, case-wide, hydrated by
  `case_service._hydrate_incident_response_records` mirroring
  `_hydrate_mitre_mapping_records`) plus the current upload's already-
  hydrated `vulnerability_records`/`linux_security_records`/
  `linux_advisory_records`/`owasp_web_records`/`owasp_security_records` into
  `IncidentInputFinding`s and calls its one tool. Cross-cutting, not
  evidence-type-gated, mirroring `MitreMappingAgent`'s routing. **Real DB
  persistence** (unlike the M4 "advisory" frameworks) — blueprint §8 names
  `IncidentResponsePlan` as a literal `Case -> 1 IncidentResponsePlan
  (nullable)` table: new `incident_response_plans` table
  (`IncidentResponsePlanRow`, `IncidentResponsePlanRepository.upsert_for_case`
  — replaces, never appends, matching the "1 nullable" cardinality), new
  `TimelineEventType.INCIDENT_RESPONSE_PLAN_GENERATED`, two new Alembic
  migrations. `CaseInvestigationResult`/`EvidenceUploadResponse` gained
  `incident_response_recommendation_count`/`incident_severity`. A documented,
  honest scope limitation (not hidden): `VulnerabilityFinding`/
  `LinuxSecurityFinding`/SAST/`WebSecurityAdvice` findings are still not
  persisted to the `findings` table (a pre-existing gap), so this agent's
  cross-upload continuity is strongest for SOC/Threat-Hunting/Phishing/
  MITRE-derived signal. No Report Generator, no LLM reasoning, no redesign
  of any prior agent/framework.
- **MITRE Mapping Agent** (`docs/adr/0022-mitre-mapping-agent.md`) —
  blueprint §7's cross-cutting MITRE Mapping Agent, the eighth concrete
  specialist agent (**closes M2 entirely**). A pre-implementation review
  found the requested mapping engine/confidence calculator/metrics/audit
  infrastructure almost entirely already existed (`core/findings/`, wired
  into `finding_service.py`/`case_service.py` since ADR-0013) — this ADR
  adds only the two blueprint-named pieces that were missing:
  `core/tools/mitre_tools.py` (`MitreMappingResolutionTool` — resolves
  already-mapped technique IDs to tactics, sub-technique parents,
  associated threat groups, associated software, and mitigations via
  `MitreLookup`, never recomputing a mapping or its confidence) and
  `core/agents/mitre_mapping_agent.py` (`MitreMappingAgent`, capability
  `mitre_technique_mapping`; returns a degraded "unmapped" result rather
  than a low-confidence guess when no mapping exists yet). Cross-cutting,
  not evidence-type-gated: routed to on every evidence upload via
  `case_service._required_capabilities_for`. New
  `CaseInvestigationState.mitre_mapping_records` field;
  `CaseInvestigationResult`/`EvidenceUploadResponse` gained
  `mitre_technique_count`/`mitre_distinct_group_count`.
  `build_investigation_graph`/`_run_specialist_agents` gained a `settings`
  parameter (needed to load the vendored MITRE dataset for this agent's
  tool). No second mapping engine, persistence layer, incident response, or
  LLM reasoning built.
- **OWASP Security Agent (AST-Based SAST)** (`docs/adr/0021-owasp-security-agent-ast-sast.md`)
  — blueprint §7's OWASP Security Agent, the last remaining M4 specialist
  agent (**closes M4 entirely**): deterministic Static Application Security
  Testing over source code, genuine AST-based analysis for Python (stdlib
  `ast` module, zero new dependencies) and pattern-based (regex) analysis
  for JavaScript/TypeScript/Java (this project has no AST library for those
  languages — an explicit, documented scope boundary, not a hidden
  shortcut). Deliberately **not** `core/owasp_web/` (ADR-0020's HTTP-traffic
  analyzer) — the two packages never import each other. New leaf package
  `core/owasp_security/` (own `SastSeverity` scale, a first-class
  `OwaspCategory` enum, a fifteen-category `VulnerabilityCategory` enum
  mapped to both `OwaspCategory` and a representative CWE id,
  `language_detector.py`, a generic `RuleEngine`/`Rule` seam extended with
  a fourth `ast_predicate` matcher kind, `python_ast_rules.py` (fifteen
  genuine AST-predicate rules covering SQL injection, XSS, command
  injection, path traversal, SSRF, hardcoded secrets, weak cryptography,
  insecure randomness, unsafe deserialization, broken authentication,
  missing input validation, dangerous file operations, open redirect,
  sensitive information exposure, and insecure configuration),
  `pattern_rules.py` (JS/TS/Java regex rules), `python_ast_analyzer.py`
  (the "AST Builder"), `pattern_analyzer.py`, `vulnerability_detection_engine.py`
  (dispatches by language), `secure_coding_advisor.py` (baseline +
  finding-triggered recommendations), `evidence_mapper.py`,
  `confidence_calculator.py` (discounts pattern-based findings relative to
  AST-based ones), `finding_generator.py`, `risk_assessment.py` (the same
  five-dimension scoring shape as prior frameworks), `analysis_engine.py`
  (the orchestrator: oversized-input guard, graceful degradation on an
  unsupported language or a genuine Python syntax error, log-injection
  sanitization applied per-snippet — never to the whole source file, which
  would destroy its newline structure before AST parsing), and metrics/
  audit modules — deliberately no DB persistence and no
  enrichment-provider seam, matching ADR-0019/0020's "advisor" framing); a
  new additive `EvidenceType.SOURCE_CODE` +
  `core/parsers/source_code_parser.py` (`SourceCodeParser` — one
  `EvidenceRecord` per file, carrying the full source text, a deliberate
  deviation from the per-line-record convention since AST parsing needs
  the whole file as one syntactic unit); the synchronous
  `core/services/owasp_security_service.py` (`assess_source_code` — no DB
  session); `core/tools/owasp_tools.py` (blueprint's exact named file,
  `OwaspSecurityAssessmentTool`); and `core/agents/owasp_security_agent.py`
  (`OwaspSecurityAgent`, capability `owasp_source_code_review`) — the
  seventh concrete specialist agent, wired into
  `core/graph/investigation_graph.py` with the same two-line pattern the
  other six established. `core/services/case_service.py`'s per-upload
  capability routing table gained the new `EvidenceType`; the evidence
  upload extension allowlist gained `.py`/`.pyw`/`.js`/`.jsx`/`.mjs`/`.cjs`/
  `.ts`/`.tsx`/`.java`. No penetration testing, active scanning, incident
  response, threat hunting, MITRE mapping, automated exploitation, or LLM
  reasoning anywhere in this package; this package never executes, `eval`s,
  or runs any analyzed source code. 138 new tests (unit covering all
  fifteen categories for Python + representative JS/TS/Java pattern
  coverage + malformed source + oversized-input guards + a regression test
  for the sanitize-whole-source bug caught during development + integration
  pipeline/performance/false-positive-reduction/per-language tests + API
  routing). Also fixed two latent `mypy --strict` issues surfaced while
  verifying this session's work: `core/owasp_web/{header_rules,
  misconfig_rules}.py` passed bare string literals where `Matcher.kind`
  expects the `MatcherKind` enum, and `core/owasp_web/advisory_engine.py`
  reused one loop variable name across three incompatible finding types.

- **OWASP Web Security Agent** (`docs/adr/0020-owasp-web-security-agent.md`)
  — a new, out-of-blueprint deterministic analyzer of HTTP traffic artifacts
  (requests/responses, security headers, cookies, JWT metadata, web server
  logs, API responses) mapped to the OWASP Top 10 (2021) taxonomy.
  Deliberately **not** blueprint §7's OWASP Security Agent (the AST-based
  source-code/API static reviewer, still unbuilt) — see the ADR for why
  these are separate. New leaf package `core/owasp_web/` (own
  `WebSecuritySeverity` scale, a first-class `OwaspCategory` enum used
  directly on `rule_engine.Rule`, a generic data-driven `RuleEngine`/`Rule`
  seam identical in shape to `core/linux_advisor`'s but never imported from
  it, `header_rules.py`'s missing-header specs + value-quality rules,
  `cookie_rules.py`'s pure structural cookie-attribute checks,
  `misconfig_rules.py`'s default pattern rules, `header_analyzer.py`/
  `cookie_analyzer.py`/`jwt_analyzer.py` (no cryptographic verification)/
  `misconfiguration_detector.py`, `category_mapper.py` (OWASP category
  name/description lookup), `finding_generator.py` (normalizes every
  analyzer's finding into the unified `OwaspFinding` shape),
  `risk_assessment.py` (a configurable, sum-to-1.0-validated
  five-dimension scoring engine), `advisory_engine.py` (the orchestrator,
  with an oversized-input guard and log-injection sanitization), and
  metrics/audit modules — deliberately no DB persistence and no
  enrichment-provider seam); new additive `EvidenceType.HTTP_TRANSACTION` +
  `core/parsers/http_transaction_parser.py` (`HttpTransactionParser`);
  `core/services/web_security_service.py` (`assess_http_transaction`,
  synchronous, no DB session); `core/tools/web_security_tools.py`
  (`WebSecurityAdvisoryTool`); and `core/agents/web_security_agent.py`
  (`WebSecurityAgent`, capability `owasp_web_security_assessment`) — the
  sixth concrete specialist agent, wired into
  `core/graph/investigation_graph.py` with the same two-line pattern the
  other five established. `core/services/case_service.py`'s per-upload
  capability routing table gained the new `EvidenceType`;
  `CaseInvestigationState` gained `owasp_web_records`;
  `CaseInvestigationResult`/`EvidenceUploadResponse` gained
  `owasp_web_finding_count`/`highest_owasp_web_risk_level`; a new
  `TimelineEventType.OWASP_WEB_ASSESSED` + Alembic migration extending
  `timeline_event_type_enum` additively. No penetration testing, active
  scanning, incident response, threat hunting, MITRE mapping, automated
  exploitation, or LLM reasoning anywhere in this package. **Does not close
  M4** — blueprint §7's AST-based OWASP Security Agent remains the
  milestone's only unbuilt, outstanding piece. 93 new tests (unit + agent/
  tool/parser + integration pipeline/performance + API routing).

- **Linux Security Advisor Agent** (`docs/adr/0019-linux-security-advisor-agent.md`)
  — blueprint §7's actual Linux Security Agent (command/permission advisor),
  explicitly distinct from ADR-0018's Linux Security *Threat Hunting*
  Framework: new leaf package `core/linux_advisor/` (own
  `LinuxAdvisorSeverity` scale, a generic data-driven `RuleEngine`/`Rule` seam
  supporting regex/literal-substring/callable-signature matchers, default
  dangerous-command rules, pure octal/rwx/`ls -l`/symbolic-mode/umask
  conversions, command/permission analyzers, a hardening advisor across
  eight categories, a configurable five-dimension risk-assessment engine, an
  orchestrating advisory engine with an oversized-input guard and
  log/command-injection sanitization, metrics, and audit — deliberately no
  DB persistence and no enrichment-provider seam); new additive
  `EvidenceType.LINUX_COMMAND_INPUT` + `core/parsers/linux_command_parser.py`
  (`LinuxCommandInputParser`); `core/services/linux_advisor_service.py`
  (`assess_linux_command_input`, synchronous, no DB session);
  `core/tools/linux_tools.py` (`LinuxSecurityAdvisoryTool`); and
  `core/agents/linux_security_agent.py` (`LinuxSecurityAgent`, capability
  `linux_security_advisory`, output type `LinuxSecurityAdvice`) — the fifth
  concrete specialist agent, wired into `core/graph/investigation_graph.py`.
  `core/services/case_service.py`'s per-upload capability routing table
  gained the new `EvidenceType`; `CaseInvestigationState` gained
  `linux_advisory_records`; `apps/api/schemas.py`/`routers/evidence.py`
  gained the two new additive response fields. New `TimelineEventType.
  LINUX_ADVISORY_ASSESSED` + Alembic migration extending
  `timeline_event_type_enum` additively.
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
- Milestone M1 completion — `Case`/`SocAnalystAgent`/first `/api/v1` routes
  (`docs/adr/0014-case-model-and-first-api-routes-shape.md`):
  - `core/db/models/case.py` (`Case`, `CaseStatus`),
    `core/db/models/timeline_event.py` (`TimelineEvent`,
    `TimelineEventType`), `core/db/models/report.py` (`Report`, `ReportType`
    — schema-only, no consumer yet), completing blueprint §8's full domain
    schema. `core/db/{case_repository,timeline_event_repository,
    report_repository}.py`.
  - Two new Alembic migrations: table creation for `cases`/`timeline_events`/
    `reports`, then a `batch_alter_table`-based follow-up (SQLite-compatible)
    turning `Evidence.case_id`/`IOC.case_id`/`Finding.case_id` into real
    foreign keys against `cases.id` — the migration ADR-0011/0012/0013 each
    explicitly owed. Verified end-to-end against a throwaway SQLite DB: full
    migration chain, FK constraints confirmed via `PRAGMA foreign_key_list`,
    clean downgrade.
  - `core/tools/scoring.py` (`RiskScoringTool`, `ScoringWeights`) — the SOC
    Analyst Agent's deterministic, configurable 0-100 risk-scoring math,
    distinct from and never duplicating `core/findings/severity.py`'s
    IOC/Finding-level scoring.
  - `core/agents/soc_analyst_agent.py` (`SocAnalystAgent`) — the first
    concrete specialist agent: summarizes evidence, classifies severity,
    detects suspected brute-force patterns from source concentration. Wired
    into `core/graph/investigation_graph.py` with zero `WorkflowEngine`/
    `routing.py` changes, confirming `docs/agent-design.md`'s stated
    extensibility contract for real.
  - `core/services/case_service.py` — `create_case`/`get_case`/`list_cases`/
    `update_case_status`/`list_timeline_for_case` plus
    `investigate_new_evidence()`, the blueprint §9 orchestrator composing
    `evidence_service` → `threat_intel_service` → `finding_service` → a
    `core/graph` run of `SocAnalystAgent`, recording a `TimelineEvent` at
    each stage. A case auto-transitions `OPEN` → `INVESTIGATING` on its
    first evidence upload. `core/services` importing `core.agents.{registry,
    soc_analyst_agent}`/`core.memory.{case_memory,repository}`/
    `core.parsers.models` directly is a fourth, separately-scoped documented
    exception (`docs/dependency-rules.md` rule 4d).
  - `apps/api/schemas.py` and the first real `/api/v1` routes:
    `routers/cases.py` (create/list/get/update-status, `GET .../timeline`),
    `routers/evidence.py` (`POST .../evidence` synchronously runs the full
    pipeline), `routers/iocs.py` and `routers/findings.py` (read-only
    lists). New runtime dependency: `python-multipart` (required by
    FastAPI's `UploadFile`).
  - 33 new tests (662 total): repository tests, `RiskScoringTool` unit
    tests, agent-level `SocAnalystAgent` tests (including a
    non-`NormalizedEvidence`-item degradation case), a full-pipeline
    integration test against the real vendored MITRE bundle and the real
    `data/sample_evidence/ssh_auth.log` fixture, and API integration tests
    via `TestClient` covering the 404 path, pagination, and the full
    upload-through-timeline flow. mypy (strict on `core/`), `ruff check`/
    `format`, and `scripts/check_dependency_rules.py` all pass.
- Case Management Extension (`docs/adr/0015-case-management-extension.md`)
  — a hardening/extension pass over Milestone M1's `Case` subsystem, not a
  new milestone:
  - `CaseStatus` extended additively with `ESCALATED`/`ON_HOLD`/
    `CONTAINED`/`RESOLVED`/`ARCHIVED` (the original `open`/`investigating`/
    `closed` values are unchanged); new `CasePriority` enum; `Case` gained
    `priority`, `risk_score`, `owner_id`/`assignee_id`, and `labels`
    (freeform, unindexed JSON metadata) columns.
  - Two new domain tables: `CaseNote` (editable analyst commentary, a
    distinct entity from `TimelineEvent.MANUAL_NOTE`'s immutable audit
    record — every note create/update/delete records a paired
    `TimelineEvent`) and `CaseTag` (an indexed, unique-constrained
    `(case_id, tag)` join table, dialect-portable across PostgreSQL/SQLite).
    New `TimelineEventType.CASE_ASSIGNED`.
  - Two new migrations verified end-to-end (upgrade/downgrade/re-upgrade
    against a throwaway SQLite DB): dialect-branching enum extension
    (`ALTER TYPE ... ADD VALUE` on PostgreSQL, `batch_alter_table` rebuild
    on SQLite) plus the two new tables.
  - `core/services/case_lifecycle.py`: a pure, exhaustively-tested
    `CaseStatus` transition table — `core/services/case_service.py::
    update_case_status` now validates every transition (raising the
    existing `BusinessRuleError`, no new exception class) *before* calling
    `CaseRepository.update_status`, which itself remains unconditional CRUD
    (transition validation cannot live in `core/db`, which must never
    import `core/services`).
  - `core/services/case_events.py` (`CaseEvent`/`CaseEventPublisher`, eight
    event types) and `core/services/case_metrics.py`
    (`CaseMetricsCollector` + `compute_case_risk_score`, a rollup of
    already-persisted `Finding.risk_score` values) — both mirror
    `core.findings.events`/`core.findings.metrics`'s shape exactly, living
    in `core/services/` rather than a new `core/cases/` leaf package.
  - `case_service.py` gained `update_case_details/_assignment/_priority/
    _labels`, `add/update/delete/list_case_note(s)`, `add/remove/
    list_case_tags`, `recompute_case_risk_score`, and an exact-match
    `(title, analyst_id)` duplicate-case guard on `create_case` (raises
    `BusinessRuleError`, `409`).
  - Ten new `/api/v1/cases/{id}/...` routes (`details`, `assignment`,
    `priority`, `labels`, `tags` GET/POST/DELETE, `notes`
    GET/POST/PATCH/DELETE). The existing `PATCH /cases/{id}` (status)
    endpoint now returns `409` on an illegal lifecycle transition instead of
    unconditionally succeeding — a behavior change to a shipped endpoint,
    not a schema/contract break.
  - 114 new tests (776 total): exhaustive transition-table coverage (every
    legal and illegal `CaseStatus` pair), repository/event/metrics unit
    tests, and integration tests covering the full escalation lifecycle,
    duplicate-case rejection, the note create/edit/delete audit trail, and
    the new API routes' success/404/409 paths. mypy (strict on `core/`),
    `ruff check`/`format`, and `scripts/check_dependency_rules.py` all pass.
- Phishing Investigation Agent, Email Parser, Prompt Guard
  (`docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`) — closes
  Milestone M2's remaining named piece and M3's own demo criterion:
  - `core/parsers/email_parser.py` (`EmailParser`) — stdlib `email` package
    only, no new dependency; new additive `EvidenceType.EMAIL`. Decodes
    header/body structure into `EvidenceRecord`s whose `raw_line` carries
    sender/reply-to/subject/body as plain text, so the existing
    `IOCExtractionEngine` extracts sender/URL/domain IOCs with zero new
    extraction code. Registered in `default_parser_registry()`; `.eml`
    uploads dispatch automatically, no router changes needed.
  - `core/security/prompt_guard.py` (`scan_text`, `PromptGuardResult`) — the
    first concrete `core/security` implementation: deterministic,
    pattern-based instruction-override/role-override/exfiltration/
    obfuscation injection detection (never an LLM call). No outbound
    `core/` dependency except `core/config` (operator-supplied
    `PROMPT_GUARD_EXTRA_PATTERNS` overrides).
  - `core/tools/phishing_tools.py` (`PhishingScoringTool`,
    `PhishingScoringWeights`) — deterministic sender/reply-to domain
    mismatch, urgency/social-engineering phrase density, and high-risk
    attachment-extension heuristics, combined with the case's already-scored
    attributed URL/domain/email IOC composite scores on an independent 0-100
    scale (never re-extracting an IOC or recomputing a threat score).
  - `core/agents/phishing_agent.py` (`PhishingAgent`, capability
    `email_triage`) — the second concrete specialist agent, screening email
    subject/body through `prompt_guard.scan_text` before use, then producing
    a `PhishingVerdict[]` via `PhishingScoringTool`. Reads
    `CaseInvestigationState.extracted_indicators` as plain
    `dict[str, object]` entries (not a typed `ScoredIOC` import — `core/agents`
    has no dependency-rules.md edge onto `core/threat_intel`). Wired into
    `core/graph/investigation_graph.py` with the same two-line pattern
    `SocAnalystAgent` established.
  - `core/services/case_service.py`: `_run_soc_analysis` generalized to
    `_run_specialist_agents`, registering both specialist agents and
    computing `required_capabilities` from the newly-ingested artifact's
    `EvidenceType` (`EMAIL` -> `email_triage`, else -> `log_analysis`,
    preserving prior behavior for every existing log-shaped format); new
    `_hydrate_attributed_iocs` reads the case's persisted `IOC` rows and
    reduces each to a plain dict before hydrating
    `CaseInvestigationState.extracted_indicators`.
  - `apps/api/schemas.py`'s `EvidenceUploadResponse` gained
    `phishing_risk_score`/`phishing_risk_label` (both `None`-defaulted,
    purely additive — no `/api/v2` cutover).
  - 45 new tests (821 total): parser/prompt-guard/tool/agent unit tests
    (including adversarial prompt-injection fixtures, malformed-email
    degradation, and attachment-risk cases), an integration test proving an
    `.eml` upload routes to `PhishingAgent` (not `SocAnalystAgent`) with its
    IOCs correctly attributed, a regression test proving the pre-existing
    SOC-only log-upload path is unchanged, and an API `TestClient` test
    proving the single `POST /evidence` endpoint dispatches `.eml` uploads
    with zero router changes. mypy (strict on `core/`), `ruff check`/
    `format`, and `scripts/check_dependency_rules.py` all pass.
- Vulnerability Assessment Framework
  (`docs/adr/0017-vulnerability-assessment-framework.md`) — closes M4's
  Vulnerability Assessment Agent piece, a third sibling leaf package to
  `core/threat_intel`/`core/findings`:
  - `core/knowledge/cvss_calculator.py` (new) — `CvssCalculator`, official
    published NVD/FIRST base-score formulas for CVSS v2.0 and v3.0/3.1
    (hand-verified against FIRST's own worked examples). CVSS v4.0 support
    is deliberately scope-cut to vector parsing/format validation only — no
    public closed-form base-score formula exists for v4.0.
  - `core/vulnerabilities/` (new leaf package) — `models.py`,
    `exceptions.py`, `cve_extractor.py` (CVE/CWE regex discovery + MITRE ID
    syntax validation), `validator.py`, `normalizer.py` (asset-ID
    derivation), `dedup.py` (configurable asset+CVE/asset+plugin/service/
    port dedup keys), `asset_correlation.py`, `confidence_engine.py`
    (four configurable, sum-to-1.0-validated dimensions), `severity.py`
    (CVSS-to-severity mapping, scanner-code fallback, priority assignment),
    `scoring.py` (`VulnerabilityThreatScoringEngine`, six configurable,
    sum-to-1.0-validated dimensions), `finding_generator.py` (groups scored
    vulnerabilities by CVE/plugin across assets — no remediation field),
    `extractor.py` (`VulnerabilityExtractionEngine`, reads structured
    scan-report fields, numeric-CVSS fallback for vector-less exports),
    `metrics.py`/`events.py`/`audit.py`, `registry.py`/`interfaces.py`
    (an unimplemented `VulnerabilityEnrichmentProvider` seam, mirroring
    `core.threat_intel`'s identical honest scope cut). Its own
    `VulnerabilitySeverity` scale (never a reuse of a sibling leaf's,
    matching `ThreatSeverity`/`FindingSeverity`'s established precedent).
  - Four new parsers: `nessus_parser.py`/`openvas_parser.py` (`.nessus`/
    OpenVAS XML via `defusedxml`, XXE-safe) and their CSV counterparts
    `nessus_csv_parser.py`/`openvas_csv_parser.py` (sharing a new
    `csv_common.py` case-tolerant column lookup helper). Four new additive
    `EvidenceType` values. All four place structured per-finding fields
    into `EvidenceRecord.normalized_fields` — zero new extraction/scoring
    code needed downstream.
  - `core/db/models/vulnerability.py` (`Vulnerability`, mirroring `IOC`'s
    shape, both `case_id`/`evidence_id` real FKs from the start) +
    `core/db/vulnerability_repository.py` + two new migrations (create
    `vulnerabilities` table; additively extend `timeline_event_type_enum`
    with `vulnerability_assessed`), both verified end-to-end
    (upgrade/downgrade/re-upgrade against a throwaway SQLite DB).
  - `core/services/vulnerability_service.py` (`VulnerabilityPipeline`, the
    ten-stage assessment pipeline: extract -> validate -> normalize ->
    deduplicate -> correlate -> score -> generate_findings -> persist ->
    publish_event -> notify_memory), mirroring
    `threat_intel_service.IOCExtractionPipeline`'s shape exactly. Gated to
    actual scan-report `EvidenceType`s only in `case_service.py`.
  - `core/tools/vuln_tools.py` (`VulnerabilityAssessmentTool`) and
    `core/agents/vulnerability_agent.py` (`VulnerabilityAssessmentAgent`,
    capability `vulnerability_assessment`) — the third concrete specialist
    agent, wired into `core/graph/investigation_graph.py` with the same
    two-line pattern `SocAnalystAgent`/`PhishingAgent` established. Reads
    `CaseInvestigationState.vulnerability_records` (new state field) as
    plain `dict[str, object]` entries — never a typed
    `core.vulnerabilities.models.VulnerabilityFinding` import (`core/agents`
    has no dependency-rules.md edge onto `core/vulnerabilities`).
  - `core/services/case_service.py`'s per-upload capability routing table
    gained the four new `EvidenceType`s -> `vulnerability_assessment`; a
    `.nessus`/OpenVAS upload now automatically fans out to
    `VulnerabilityAssessmentAgent` instead of `SocAnalystAgent`.
    `apps/api/schemas.py`'s `EvidenceUploadResponse` gained
    `vulnerability_finding_count`/`highest_vulnerability_score` (both
    `None`-defaulted, purely additive).
  - 168 new tests (989 total): CVSS calculator unit tests against
    hand-verified FIRST reference vectors, unit tests for every
    `core/vulnerabilities` module, all four new parsers (including an XXE
    payload test per scan-report XML format), the repository, the tool, the
    agent, an integration test proving a real Nessus scan (two hosts
    sharing one CVE) correctly deduplicates/correlates/aggregates end to
    end, a malformed-report regression test, and an API `TestClient` test
    proving the single `POST /evidence` endpoint dispatches `.nessus`
    uploads with zero router changes. No remediation planning, Incident
    Response, or LLM reasoning — explicitly out of scope. mypy (strict on
    `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py`
    all pass.
- Linux Security Threat Hunting Framework
  (`docs/adr/0018-linux-security-threat-hunting-framework.md`) — closes M4's
  Threat Hunting Agent piece (blueprint §7's "identify multi-stage patterns
  (recon -> exploitation -> persistence)"), a fourth sibling leaf package to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`. **Not** the
  blueprint §7 Linux Security Agent (a narrow command/permission-string
  explainer), which remains unbuilt, separate, still-open M4 scope:
  - `core/linux_security/` (new leaf package) — `models.py` (a single shared
    `LinuxSecurityCandidate` shape across fifteen detection categories,
    rather than fifteen near-identical models; its own
    `LinuxSecuritySeverity` scale), `exceptions.py`, `normalizer.py`
    (`EvidenceRecord` -> `LinuxLogEvent`, a documented best-effort journald
    `_`-field supplement, a log-injection guard stripping control
    characters), `ssh_auth_analyzer.py` (sliding-window brute force,
    failed-login spike, root login, compromise-after-brute-force),
    `sudo_analyzer.py` (sensitive-file access, shell-escape-to-root,
    repeated sudo auth failures), `privilege_escalation.py` (new user/
    deletion/password change/group escalation/su-to-root, plus a combined
    new-user-then-escalation multi-step pattern), `cron_analyzer.py`/
    `service_analyzer.py` (suspicious cron jobs and service starts;
    `service_analyzer.py`'s heuristic is honestly documented as weaker —
    syslog rarely carries full unit-file content), `process_detector.py`
    (the single shared reverse-shell/suspicious-command regex set every
    other analyzer delegates to), `persistence_detector.py` (cross-category
    aggregation into `persistence_mechanism` findings),
    `authentication_timeline.py` (this run's own auth reconstruction —
    explicitly documented as distinct from the blueprint §13 Threat Timeline
    UI feature, which stays M6), `confidence_engine.py`/`scoring.py`
    (a confidence engine and a seven-dimension `LinuxThreatScoringEngine`,
    both configurable and sum-to-1.0-validated), `finding_generator.py`
    (groups scored candidates by `(category, subject)` — no remediation
    field), `extractor.py` (`LinuxSecurityAnalysisEngine`, the orchestrating
    engine with an oversized-evidence guard), `metrics.py`/`events.py`/
    `audit.py`, `registry.py`/`interfaces.py` (an unimplemented
    `LinuxSecurityEnrichmentProvider` seam, mirroring
    `core.vulnerabilities`'s identical honest scope cut).
  - No new parsers or `EvidenceType` values needed — `SshAuthParser`/
    `SyslogParser` already emit everything this package's analyzers read.
  - `core/db/models/linux_security_finding.py` (`LinuxSecurityFindingRow`,
    mirroring `Vulnerability`'s shape, both `case_id`/`evidence_id` real FKs
    from the start) + `core/db/linux_security_finding_repository.py` + two
    new migrations (create `linux_security_findings` table; additively
    extend `timeline_event_type_enum` with
    `linux_security_finding_detected`), both verified end-to-end.
  - `core/services/linux_security_service.py` (`LinuxSecurityPipeline`, the
    ten-stage analysis pipeline: Evidence Normalization -> Authentication
    Analysis -> Privilege Analysis -> Persistence Analysis -> Behavior
    Detection -> Threat Scoring -> Finding Generation -> Persistence ->
    Event Publication -> Case/Timeline Notification), mirroring
    `vulnerability_service.VulnerabilityPipeline`'s shape exactly. Gated to
    `SSH_AUTH`/`SYSLOG` evidence only in `case_service.py` — deliberately
    not `EvidenceType.JSON` (documented scope decision, mirrors ADR-0017
    point 9).
  - `core/tools/linux_security_tools.py` (`LinuxSecurityAssessmentTool`) and
    `core/agents/threat_hunter_agent.py` (`ThreatHunterAgent`, capability
    `cross_log_threat_hunting`, output `ThreatHuntingReport`) — the fourth
    concrete specialist agent, wired into
    `core/graph/investigation_graph.py` with the same two-line pattern the
    other three established. Reads
    `CaseInvestigationState.linux_security_records` (new state field) as
    plain `dict[str, object]` entries — never a typed
    `core.linux_security.models.LinuxSecurityFinding` import (`core/agents`
    has no dependency-rules.md edge onto `core/linux_security`).
  - `core/services/case_service.py`'s per-upload capability routing table
    changed shape (`dict[EvidenceType, str]` -> `dict[EvidenceType,
    tuple[str, ...]]`): `SSH_AUTH`/`SYSLOG` now route to *both*
    `SocAnalystAgent` and `ThreatHunterAgent` — a single evidence type
    requiring more than one specialist capability, proven end-to-end with
    zero Planning Agent/routing framework changes.
    `apps/api/schemas.py`'s `EvidenceUploadResponse` gained
    `linux_security_finding_count`/`highest_linux_security_risk_score`
    (both `None`-defaulted, purely additive).
  - 138 new tests (1127 total): unit tests for every `core/linux_security`
    module (including a malformed/adversarial-input case per module —
    corrupted log lines, invalid timestamps, log-injection-shaped input,
    an oversized-artifact guard test), the repository, the tool, the agent,
    two integration tests proving a real `ssh_auth.log` (brute force +
    compromise) and a crafted syslog fixture (sudo `/etc/shadow` access,
    new-user-then-`usermod -aG sudo` escalation, cron piping curl to bash)
    detect end-to-end through persistence, a malformed-log regression test,
    an API `TestClient` test proving an `auth.log` upload now also routes to
    `ThreatHunterAgent` alongside `SocAnalystAgent`, and a performance test
    processing 40,000 synthetic log records within a bounded time. No
    Incident Response, remediation, or LLM reasoning — explicitly out of
    scope. mypy (strict on `core/`), `ruff check`/`format`, and
    `scripts/check_dependency_rules.py` all pass.

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
