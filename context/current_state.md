# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented blueprint §7's **Incident Response Agent**
(`docs/adr/0023-incident-response-agent.md`), **partially closing M5** — the
Incident Response half of M5 is done; the Report Generator Agent half
remains open. This is the **ninth** concrete specialist agent (after
`SocAnalystAgent` M1, `PhishingAgent` M2, `VulnerabilityAssessmentAgent`/
`ThreatHunterAgent`/`LinuxSecurityAgent`/`WebSecurityAgent`/
`OwaspSecurityAgent` M4, `MitreMappingAgent` M2).

**Before writing any code**, this session worked out a real architecture
question the task brief didn't answer on its own: blueprint §7 says the
Incident Response Agent "pulls from every other agent's output already in
case state — never re-parses evidence itself," but
`core/graph/workflow_engine.py`'s `_make_node` docstring documents, as an
empirically-verified fact, that sibling nodes fanned out in the same
LangGraph superstep each run against their own private deep copy of the
pre-superstep state — a node can never see another node's writes from the
same run (confirmed further by `core/agents/planning_agent.py`: every
`PlannedStep` it emits has `depends_on=()`, and `core/graph/routing.py` only
ever fans out to entry steps — there is no dependency-aware second-wave
dispatch implemented anywhere). The naive design ("read
`state.agent_outputs[other_agent.name]`") would have silently returned
empty results for every case. `docs/adr/0023-incident-response-agent.md`
documents the actual resolution: this agent reads the same *pre-hydrated
input* `*_records` fields every other specialist already reads
(`vulnerability_records`, `linux_security_records`, `linux_advisory_records`,
`owasp_web_records`, `owasp_security_records`, `mitre_mapping_records` —
all populated onto `CaseInvestigationState` *before* the graph runs, not
written during it) plus a new case-wide `incident_response_finding_records`
field (hydrated from the case's already-persisted `Finding` rows, mirroring
`MitreMappingAgent`'s `mitre_mapping_records` pattern exactly) — never
sibling `agent_outputs`. This was resolved and documented via ADR before any
implementation code was written, per the project's own "stop and explain
before writing code" rule.

**What this session actually built:**
- **`core/incident_response/`** (new leaf package, ninth peer to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`/
  `core/linux_security`/`core/linux_advisor`/`core/owasp_web`/
  `core/owasp_security`) — the task's named strongly-typed models
  (`models.py`: `IncidentSeverity`, `ResponsePriority`, `ResponseCategory`
  — the task's exact eleven named action kinds, `ResponsePhase` — the
  task's exact six named phases, `ResponseTimeframe`, `ResponseEvidence`,
  `ResponseAction`, `ResponseRecommendation`, `ResponseMetrics`,
  `IncidentResponsePlan` with derived, never-duplicated `@property` phase/
  timeframe groupings), `exceptions.py` (narrow hierarchy), `inputs.py`
  (`IncidentInputFinding` — the one normalized shape every upstream
  subsystem's already-computed signal is reduced to before this package
  ever sees it), `severity_classifier.py` (`IncidentSeverityClassifier` —
  case-level severity rollup with configurable escalation thresholds),
  `playbook_rules.py` (the deterministic rule engine: a real ATT&CK
  tactic-ID -> `ResponseCategory` mapping table for all fourteen enterprise
  tactics, a keyword fallback, a severity-only last resort, plus the static
  per-category `CategoryTemplate` table naming phase/timeframe/base-priority/
  title/description/expected-impact for all eleven categories),
  `risk_prioritizer.py` (`RiskPrioritizer` — one finding+category -> a fully
  specified `ResponseRecommendation`, severity-driven priority escalation/
  de-escalation), `action_ordering.py` (`order_recommendations` — dedups
  recommendations resolving to the same category+target across findings by
  merging evidence/finding-ids/technique-ids, then sorts by priority ->
  NIST-phase order -> risk score -> category and assigns `execution_order`),
  `confidence_calculator.py` (plan-level confidence/risk-score rollups,
  confidence discounted by the fraction of skipped/malformed input records),
  `response_plan_engine.py` (`ResponsePlanEngine` — the task's named
  pipeline orchestrator: classify severity -> match categories -> prioritize
  -> order -> calculate confidence -> build `IncidentResponsePlan`, with a
  documented degraded-not-crashed outcome for zero findings, zero matched
  categories, and an oversized-finding-set guard), `metrics.py`
  (`IncidentResponseMetricsCollector`), `audit.py` (structured audit-event
  emission + timing) — mirroring `core/owasp_security`/`core/linux_advisor`'s
  established leaf-package shape exactly. Deterministic throughout — no LLM
  reasoning anywhere in this package (task requirement), verified by an
  explicit reproducibility test (`test_incident_response_response_plan_engine.
  py::test_generation_is_deterministic_given_the_same_input`).
- **`core/tools/ir_tools.py`** (new, blueprint's exact named file) —
  `IncidentResponsePlanGenerationTool`. Unlike `owasp_tools.py`/
  `web_security_tools.py` (thin dict-shaped aggregators with no cross-leaf
  import), this tool's `run()` is a thin wrapper around
  `core.incident_response.response_plan_engine.ResponsePlanEngine` — the
  same shape `core.tools.mitre_tools.MitreMappingResolutionTool` already
  established for wrapping `core.knowledge.mitre.lookup.MitreLookup`
  directly. Its input stays typed (not dict-shaped): a new, narrowly-scoped
  dependency-rules.md exception (**rule 5b**) permits this one
  `core/tools/*.py` file — and no other — to import `core/incident_response`
  directly, mirroring rule 5's existing `core/knowledge` exception for
  `mitre_tools.py`.
- **`core/agents/incident_response_agent.py`** (new) — `IncidentResponseAgent`,
  the ninth concrete specialist agent, capability
  `incident_response_synthesis`. Deliberately thin: normalizes six different
  `CaseInvestigationState` record fields (see Decision 1 above) into
  `IncidentInputFinding`s via one small converter function per source
  (`_finding_from_persisted_record`, `_finding_from_vulnerability_record`,
  `_finding_from_linux_security_record`, `_finding_from_linux_advisory_record`,
  `_finding_from_owasp_web_record`, `_finding_from_owasp_security_record`,
  each skip-on-malformed, never crashing) and calls
  `IncidentResponsePlanGenerationTool`. Returns a `DEGRADED`,
  zero-recommendation "insufficient evidence" result — never a forced
  guess — when no findings are available yet, exactly matching
  `MitreMappingAgent`'s "unmapped rather than a low-confidence guess"
  precedent. **Needs no new dependency-rules.md exception of its own** — it
  calls its tool through the normal `BaseAgent.use_tool` mechanism and only
  imports `core.tools.ir_tools`'s typed Input/Output models, the identical
  "agent imports its own tool's typed contracts, never the leaf package the
  tool wraps" shape `MitreMappingAgent` follows for `core.tools.mitre_tools`.
- **Real DB persistence — unlike every M4 "advisory" framework.** Blueprint
  §8's DB design literally names `Case ├─ ... └─ 1 IncidentResponsePlan
  (nullable)`; the task brief's pipeline explicitly names "Persist Response
  Plan" as a stage. New `core/db/models/incident_response_plan.py`
  (`IncidentResponsePlanRow` — named "Row," not "IncidentResponsePlan," to
  avoid a same-name collision with the Pydantic model, mirroring
  `LinuxSecurityFindingRow`'s identical precedent; a real unique constraint
  on `case_id`, not just convention) and
  `core/db/incident_response_plan_repository.py`
  (`IncidentResponsePlanRepository.upsert_for_case` — replaces the existing
  row, never appends a second one for the same case, matching blueprint's
  literal "1 nullable" cardinality; takes the plan as a plain
  `dict[str, object]`, not the typed Pydantic model, so
  `core/services/case_service.py` never needs its own new import edge onto
  `core/incident_response` — that Pydantic model stays imported only inside
  `core/db`, the same "leaf imports a sibling leaf's model for column
  typing" precedent `core/db/models/finding.py` already set for
  `core.findings.models.FindingSeverity`). Two new, additive Alembic
  migrations (`f3a9c1d7e2b5` creates `incident_response_plans`;
  `b7e4d2f8a1c9` extends `timeline_event_type_enum` with the new
  `TimelineEventType.INCIDENT_RESPONSE_PLAN_GENERATED`).
- **Cross-cutting routing, not evidence-type-gated** — mirroring
  `MitreMappingAgent`'s identical routing exactly:
  `incident_response_synthesis` is appended to *every* evidence type's
  required-capability list in `core/services/case_service.py`'s
  `_required_capabilities_for`.
- **`core/services/case_service.py`** (modified) — new
  `_hydrate_incident_response_records` mirrors `_hydrate_mitre_mapping_records`
  exactly (case-wide, `json.loads` on `Finding.finding_data_json`, never a
  typed `core.findings` import — this module still has **no** new import
  edge onto `core/findings` or `core/incident_response`). New
  `_persist_incident_response_plan` reads the agent's plain-dict plan output
  and calls the repository, records
  `TimelineEventType.INCIDENT_RESPONSE_PLAN_GENERATED`, and returns
  `(recommendation_count, incident_severity)` for `None, None` on the
  documented "no plan yet" outcome (never `(0, None)` — the same
  "insufficient evidence" vs. "no findings" distinction
  `_extract_mitre_mapping` already established). `_run_specialist_agents`
  registers the ninth agent; `CaseInvestigationResult` gained
  `incident_response_recommendation_count`/`incident_severity`.
  `EvidenceUploadResponse` (`apps/api/schemas.py`/`routers/evidence.py`)
  passes them through.
- **`core/graph/{state,investigation_graph}.py`** (modified) —
  `CaseInvestigationState` gained `incident_response_finding_records:
  list[Any]` (case-wide scope, same `operator.add` shape as
  `mitre_mapping_records`). `IncidentResponseAgent` registered/wired as the
  graph's ninth node with the same two-line pattern every prior specialist
  established.
- **Testing** — 66 new tests: nine `core/incident_response` unit-test
  modules (models, severity classification including escalation/
  double-escalation/critical-cap behavior, the playbook rule engine's
  three-strategy precedence and dedup, risk prioritization's escalation/
  de-escalation/fallback-risk-score math, action ordering's dedup+merge+sort,
  confidence/risk-score rollups, and the full pipeline engine including a
  determinism test and an oversized-input guard test), `test_tools_ir_tools.py`,
  `test_agents_incident_response_agent.py` (empty-state degraded outcome,
  synthesis from persisted-finding records, synthesis from vulnerability
  records, malformed-record skip-don't-crash, findings-list append), and
  `test_db_incident_response_plan_repository.py` (upsert-creates,
  upsert-replaces-not-appends, find-by-case). Plus one extended assertion in
  the existing end-to-end `test_case_service_pipeline.py` SSH-auth-log test
  (asserting `incident_response_recommendation_count > 0` and the new
  timeline event type) and the `test_investigation_graph.py` node-set
  assertion extended to the ninth agent. Full pytest suite (1604 tests, up
  from 1546), `ruff check`/`format --check`, and
  `scripts/check_dependency_rules.py` all pass. New/changed files are
  individually `mypy --strict` clean (the pre-existing, unrelated numpy/
  pandas whole-repo `mypy` failure — see Known Issues — is unchanged, not
  caused by this session).

**Explicitly NOT built this session:** the Report Generator Agent (M5's
other half — still not started); any closing of the pre-existing
"Vulnerability/Linux/OWASP/Web findings aren't persisted to the `findings`
table" gap (a deliberate, documented scope boundary — closing it would mean
redesigning five already-complete, independently-shipped frameworks,
directly violating "never redesign completed modules"; this session's
Incident Response Agent's cross-upload continuity is honestly weaker for
those four subsystems as a direct, disclosed consequence — see ADR-0023
Decision 1 and Known Issues below); an "analyst requests it" on-demand
regeneration API route (the plan currently only regenerates on the next
evidence upload, cross-cutting); any redesign of `core/graph/workflow_engine.py`,
`core/graph/routing.py`, `core/agents/planning_agent.py`,
`core/agents/coordinator.py`, or any prior specialist agent/framework.

---

### M2's MITRE Mapping Agent (prior session, unchanged)

Prior session implemented blueprint §7's **MITRE Mapping Agent**
(`docs/adr/0022-mitre-mapping-agent.md`), closing **M2 entirely** — the last
milestone that stayed open after M4 closed last session. This is the
**eighth** concrete specialist agent (after `SocAnalystAgent` M1,
`PhishingAgent` M2, `VulnerabilityAssessmentAgent`/`ThreatHunterAgent`/
`LinuxSecurityAgent`/`WebSecurityAgent`/`OwaspSecurityAgent` M4).

**Before writing any code, this session found a real architecture conflict**
and surfaced it to the user rather than proceeding silently (per the
project's own "stop and explain before writing code" rule): the task brief
asked for a full, new "MITRE Mapping framework" — a Mapping Engine,
Technique Matching Engine, Confidence Calculator, Mapping Metrics, Audit
Events, evidence aggregation, deduplication, persistence — but a review of
`core/findings/` and `core/knowledge/mitre/` found **almost all of this
already existed**, built under ADR-0013 two sessions ago and already wired
into production via `core.services.finding_service.
generate_findings_for_case`, called on every evidence upload from
`case_service.investigate_new_evidence`. Building a parallel implementation
would have violated the constitution's "never duplicate functionality" and
"one clear home" rules. The user chose the **thin agent + tool** scope:
reuse the existing engine entirely and add only the two blueprint-named
pieces that were genuinely missing.

**What this session actually built:**
- **`core/tools/mitre_tools.py`** (new, blueprint's exact named file) —
  `MitreMappingResolutionTool`. Never re-derives a technique mapping or its
  confidence (that stays `core.findings.mapping_engine.MitreMappingEngine`'s
  job). Resolves already-mapped technique IDs via
  `core.knowledge.mitre.lookup.MitreLookup` to: tactic phases
  (`tactics_for_technique`), sub-technique parent IDs (ATT&CK's own
  `"T1110.001"` dot convention, parsed by a small pure `parent_technique_id`
  helper — no separate parent/child data needed), associated threat groups
  (`groups_using_technique` — previously unused by anything in this
  codebase), associated software (`software_using_technique` — also
  previously unused), and mitigations (`mitigations_for_technique`).
  Aggregates ATT&CK matrix-style tactic coverage counts and distinct
  group/software counts across the whole case. Unlike every other tool in
  this package, its constructor takes an injected `MitreLookup` and its
  input stays typed (not dict-shaped): `core/tools` is explicitly allowed to
  import `core/knowledge` directly (docs/dependency-rules.md rule 5).
  Gracefully degrades (`unresolved_technique_ids`) for a technique_id absent
  from the loaded dataset, never raising.
- **`core/agents/mitre_mapping_agent.py`** (new) — `MitreMappingAgent`, the
  eighth concrete specialist agent, capability `mitre_technique_mapping`.
  Deliberately thin: reads
  `CaseInvestigationState.mitre_mapping_records` (hydrated by
  `case_service.py` from the case's already-persisted
  `Finding.mitre_mappings`) and calls `MitreMappingResolutionTool` to
  produce a case-level `MitreCaseMappingSummary`. Returns a `DEGRADED`,
  zero-technique "unmapped" result — never a forced low-confidence guess —
  when no mapping exists yet for the case, exactly matching blueprint §7's
  documented failure handling. **Unlike every other specialist agent**, this
  one is explicitly permitted to import `core.knowledge.mitre` directly
  (docs/dependency-rules.md rule 4/4c: "core/agents may import ...
  core/knowledge ... Finding/MITRE mapping only") — MITRE reference data is
  shared knowledge, not a sibling leaf's private model like every other
  specialist agent's owning package is.
  `default_mitre_mapping_agent_tool_registry(settings=...)` is this
  codebase's first agent-tool-registry factory that needs a `Settings`
  parameter (to load the vendored MITRE dataset for its tool's injected
  `MitreLookup`).
- **Cross-cutting routing, not evidence-type-gated** — unlike every other
  specialist, `MitreMappingAgent`'s capability is appended to *every*
  evidence type's required-capability list in
  `core/services/case_service.py`'s `_required_capabilities_for`, since
  Finding generation (and therefore MITRE mapping) already runs
  unconditionally on every evidence upload, regardless of which other
  specialist(s) that evidence type also routes to.
- **`core/services/case_service.py`** (modified) — new
  `_hydrate_mitre_mapping_records` reads the case's persisted
  `Finding.finding_data_json` rows (via
  `core.services.finding_service.list_findings_for_case`, already imported)
  and reduces each `mitre_mappings` entry to a plain dict via
  `json.loads` — never importing `core.findings.models.FindingRecord`
  directly (that import edge belongs to `finding_service.py` specifically
  per rule 4c). Scoped to the whole case (every Finding, not just the
  current upload's), matching blueprint §13's MITRE ATT&CK matrix heatmap,
  which is inherently case-wide. `_run_specialist_agents` and
  `build_investigation_graph` both gained a `settings: Settings` parameter
  (the latter defaults to `Settings()` when omitted — every field has a
  default, so every existing caller still works unchanged).
  `CaseInvestigationResult` gained `mitre_technique_count`/
  `mitre_distinct_group_count`; `EvidenceUploadResponse`
  (`apps/api/schemas.py`/`routers/evidence.py`) passes them through.
- **`core/graph/{state,investigation_graph}.py`** (modified) —
  `CaseInvestigationState` gained `mitre_mapping_records: list[Any]` (the
  same uniform `list[Any]`/`operator.add` shape every other `*_records`
  field has — `core/graph` itself has no import edge onto
  `core/findings`/`core/knowledge`, even though `core/agents` does).
  `MitreMappingAgent` registered/wired as the graph's eighth node with the
  same two-line pattern every prior specialist established.
- **Testing** — 13 new tests: `tests/unit/test_tools_mitre_tools.py` (tool
  resolution against a small hand-built `MitreDataset` — tactic/group/
  software/mitigation resolution, sub-technique parent resolution, unknown
  technique graceful degradation, max-confidence + finding-id dedup across
  repeated mappings, top-N truncation, empty input), `tests/unit/
  test_agents_mitre_mapping_agent.py` (agent-level: empty-records
  "unmapped" degraded result, malformed-record skip-don't-crash, unknown
  technique reported not dropped, deterministic confidence, findings-list
  append), plus one extended assertion in the existing end-to-end
  `test_case_service_pipeline.py` SSH-auth-log test (12 failed logins ->
  USERNAME+IPV4 IOCs -> `R-T1110-brute-force` rule -> `mitre_technique_count
  > 0`, proving the whole pipeline wired together for real) and the
  `test_investigation_graph.py` node-set assertion extended to the eighth
  agent. Full pytest suite (1546 tests, up from 1533), `ruff check`/`format
  --check`, and `scripts/check_dependency_rules.py` all pass. New/changed
  files are individually `mypy --strict` clean (the pre-existing,
  unrelated numpy/pandas whole-repo `mypy` failure — see Known Issues — is
  unchanged, not caused by this session).

**Explicitly NOT built this session:** a second MITRE mapping engine,
confidence calculator, metrics collector, audit module, evidence
aggregator, or deduplication engine (all already exist in `core/findings/`
and are reused as-is); any new DB persistence (this agent reads
already-persisted data, writes nothing new); incident response, report
generation, or LLM reasoning of any kind; any redesign of
`core/findings/`, `core/knowledge/mitre/`, or any prior agent/framework.

---

### M0–M4 + M2's OWASP Security Agent (unchanged from prior sessions)

Previous session implemented blueprint §7's **OWASP Security Agent** end-to-end
— an explicit ADR: **ADR-0021, OWASP Security Agent (AST-Based SAST)**
(`docs/adr/0021-owasp-security-agent-ast-sast.md`). This was the last
remaining M4 specialist agent — blueprint's exact scope: *"source code /
API static review... detect SQLi/XSS/broken-auth patterns, map to OWASP
Top-10 (2021)... Tools used: `owasp_tools.py` (AST-based static analysis,
not just regex, for the SQLi/XSS detectors)."* **This closes M4 entirely.**
This is the **seventh** concrete specialist agent (after `SocAnalystAgent`
M1, `PhishingAgent` M2, `VulnerabilityAssessmentAgent` M4, `ThreatHunterAgent`
M4, `LinuxSecurityAgent` M4, `WebSecurityAgent` M4/ADR-0020), proving the
same three-step extension pattern a seventh time.

**This is not** `core/owasp_web/` (ADR-0020's out-of-blueprint Web Security
Agent — HTTP traffic/header/cookie/JWT analysis, no source code, no AST).
The task prompt itself explicitly named the zero-overlap requirement; a
pre-implementation review confirmed the two packages have disjoint input
shapes (`EvidenceType.SOURCE_CODE` vs. `EvidenceType.HTTP_TRANSACTION`),
disjoint agent/tool/state-field names, and never import each other.

**Key scope decision (no new dependency):** the repo has no JavaScript/
TypeScript/Java AST library (`requirements.txt` checked before writing any
code). Rather than add one unjustified by this task alone, or silently
skip those languages, this session made the honest split explicit and
structural: **Python gets genuine AST analysis** via the stdlib `ast`
module (zero new dependencies, satisfies blueprint's "not just regex" bar
for the reference language); **JavaScript/TypeScript/Java get pattern-based
(regex) analysis** through the same generic `RuleEngine` design already
established (ADR-0019/0020), with `confidence_calculator.py` structurally
discounting pattern-based findings relative to AST-based ones so this
difference is visible to consumers, not hidden. Documented in ADR-0021 as
a deliberate, ADR-gated scope boundary — a future session could add a real
JS/TS/Java parser (e.g. tree-sitter) behind its own ADR without touching
this framework's shape.

### M0–M4 (Vulnerability Assessment, Linux Security Threat Hunting, Linux Security Advisor, OWASP Web Security) frameworks (unchanged from prior sessions)

Configuration, logging, shared contracts, DB foundation, FastAPI app,
governance, `core/agents`/`core/tools`/`core/graph` framework,
`core/memory`/`core/knowledge` framework, `core/threat_intel` framework (20
IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine),
`Case`/`Evidence`/`Finding`/`TimelineEvent`/`Report`/`Vulnerability`/
`LinuxSecurityFindingRow` domain models, `SocAnalystAgent`, `PhishingAgent`,
`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`, `LinuxSecurityAgent`,
`WebSecurityAgent`, `core/vulnerabilities/` (ADR-0017),
`core/linux_security/` (ADR-0018), `core/linux_advisor/` (ADR-0019),
`core/owasp_web/` (ADR-0020), `core/security/prompt_guard.py`, the Case
lifecycle/ownership/tags/notes/events/metrics extension (ADR-0015), and
`core/services/case_service.py`'s `investigate_new_evidence()` orchestrator
— all unchanged except where explicitly noted below.

### OWASP Security Agent Framework (new this session, ADR-0021)

- **`core/owasp_security/`** (new leaf package, seventh peer to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`/
  `core/linux_security`/`core/linux_advisor`/`core/owasp_web`, matching
  `core/linux_advisor`/`core/owasp_web`'s lightest-weight shape — no DB
  persistence, no `registry.py`/`interfaces.py` enrichment-provider seam) —
  - `models.py`: own `SastSeverity` scale, a first-class `OwaspCategory`
    enum (own copy — never imported from `core.owasp_web.models`), a
    fifteen-category `VulnerabilityCategory` enum (the task's named
    detection surface: SQL Injection, XSS, Command Injection, Path
    Traversal, SSRF, Hardcoded Secrets, Weak Cryptography, Insecure
    Randomness, Unsafe Deserialization, Broken Authentication, Missing
    Input Validation, Dangerous File Operations, Open Redirect, Sensitive
    Information Exposure, Insecure Configuration) with `CATEGORY_OWASP_MAP`/
    `CATEGORY_CWE_MAP` lookup tables (one canonical CWE id per category),
    `SourceLanguage` (`PYTHON`/`JAVASCRIPT`/`TYPESCRIPT`/`JAVA`/`UNKNOWN`,
    with `AST_SUPPORTED_LANGUAGES` naming Python as the only AST-analyzed
    language), `SourceFinding` (per-analyzer output, `is_ast_based` flag),
    `SastFinding` (the task's unified finding shape: category, OWASP
    category, CWE id, severity, confidence, evidence reference,
    explanation, recommended remediation), `SastAdvice` (the aggregate
    output), `SecureCodingRecommendation`, `MatcherKind` (extended with a
    fourth `ast_predicate` kind beyond `core.owasp_web`'s three),
    `RiskDimensionScores`.
  - `exceptions.py`: narrow hierarchy (`UnsupportedLanguageError`,
    `AstParseError`, `OversizedSourceInputError`).
  - `rule_engine.py`: `RuleEngine`/`Rule` — the task's named "Rule Engine"
    requirement (versioning, priority, categories, OWASP mapping, CWE
    mapping, severity, enable/disable, metadata, composable rules), own
    copy (never imported from `core.owasp_web.rule_engine` — leaves never
    share code sideways), extended with `ast_predicate` matcher kind:
    `evaluate_text(text)` for `regex`/`literal_substring`/
    `callable_signature` rules, `evaluate_ast(tree, source_lines)` for
    `ast_predicate` rules (dispatches to a named predicate registered via
    `register_ast_predicate`, returning `(line_number, snippet)` tuples so
    every AST finding carries a real line number). `Rule.owasp_category`/
    `Rule.cwe_id` are derived properties from `Rule.category` via the
    shared mapping tables — never repeated per rule.
  - `language_detector.py`: `LanguageDetector` — the task's named
    "Language Detection" capability; extension-first (`.py`/`.js`/`.jsx`/
    `.mjs`/`.cjs`/`.ts`/`.tsx`/`.java`), content-heuristic fallback,
    `SourceLanguage.UNKNOWN` a real, reachable outcome.
  - `python_ast_rules.py`: fifteen registered AST predicates (one per
    `VulnerabilityCategory`) + `DEFAULT_PYTHON_AST_RULES` — genuine
    `ast.walk()`-based detection (e.g. SQL injection: a `.execute()`-family
    call whose argument is a dynamically-built string rather than a
    constant; command injection: `os.system`/`os.popen`/`subprocess`
    `shell=True`; unsafe deserialization: `pickle.load(s)`/bare `eval`/
    `exec`/unsafe `yaml.load`; hardcoded secrets: an assignment to a
    secret-named variable of a non-trivial string constant; etc.). Every
    predicate's docstring states its detection basis and known
    false-positive shape explicitly (heuristic, not full taint tracking —
    ADR-0021 point 7).
  - `pattern_rules.py`: `DEFAULT_PATTERN_RULES` — regex-based rules for
    JavaScript/TypeScript/Java (e.g. `child_process.exec`/
    `Runtime.getRuntime().exec` for command injection, `.innerHTML =` for
    XSS, `Math.random()`/`new Random()` for insecure randomness,
    `MessageDigest.getInstance("MD5")` for weak cryptography,
    `rejectUnauthorized: false` for insecure configuration) — this
    project's honest, documented fallback for languages with no AST
    facility here.
  - `python_ast_analyzer.py`: `PythonAstAnalyzer` + `build_ast` (the task's
    named "AST Builder") — `ast.parse()`, raising `AstParseError` on a
    genuine `SyntaxError` rather than propagating it raw.
  - `pattern_analyzer.py`: `PatternSourceAnalyzer` — runs pattern rules
    line-by-line (real line numbers, unlike a whole-file regex scan).
  - `vulnerability_detection_engine.py`: `VulnerabilityDetectionEngine` —
    the task's named "Vulnerability Detection Engine"; dispatches to
    `PythonAstAnalyzer` for Python, `PatternSourceAnalyzer` for everything
    else, raises `UnsupportedLanguageError` for `UNKNOWN`.
  - `secure_coding_advisor.py`: `SecureCodingAdvisor` — the task's named
    "Secure Coding Advisor"; mirrors `hardening_advisor.py`'s shape (one
    baseline recommendation per category, always surfaced, plus
    finding-triggered recommendations naming the specific file/line).
  - `evidence_mapper.py`: `map_evidence_reference` — the task's named
    "Evidence Mapping"; a pure `"{file}:{line}: {snippet}"` formatter.
  - `confidence_calculator.py`: `calculate_confidence` — the task's named
    "Confidence Calculator"; `1.0`x multiplier for AST-based findings,
    `0.75`x for pattern-based ones (a real, documented reliability signal).
  - `finding_generator.py`: `FindingGenerator` — the task's named "Finding
    Generator"; normalizes `SourceFinding` into the unified `SastFinding`
    shape via `confidence_calculator`/`evidence_mapper`.
  - `risk_assessment.py`: `RiskAssessmentEngine`/`SastRiskWeights` — the
    same five-configurable-dimension, sum-to-1.0-validated shape as
    `core.owasp_web.risk_assessment` (own copy).
  - `text_utils.py`: `sanitize_snippet` — a tiny, dependency-free module
    (avoids a circular import between `analysis_engine.py` and the
    analyzer modules) applying the log-injection control-character strip
    **only to individual extracted snippets**, never to a whole source
    file (see Key Decisions below for the bug this avoided).
  - `analysis_engine.py`: `SourceCodeAnalysisEngine` — the task's named
    pipeline orchestrator: language detection -> oversized-input guard ->
    AST parse (Python) / pattern match (else) -> secure-coding advice ->
    finding generation -> confidence calculation -> risk assessment.
    Degrades gracefully (never crashes) on an unsupported/undetected
    language or a genuine Python syntax error, in both cases returning a
    zero-finding `SastAdvice` with `parse_degraded=True` and an explicit
    explanation.
  - `metrics.py`/`audit.py`: `SastMetricsCollector` (files/lines analyzed,
    findings by category, rule matches by id, failures, timing) and
    structured audit-event emission + timing, mirroring the established
    shape in `core/owasp_web`/`core/linux_advisor`.
- **New `EvidenceType.SOURCE_CODE`** (`core/parsers/models.py`, purely
  additive) + **new parser `core/parsers/source_code_parser.py`**
  (`SourceCodeParser`) — deliberately **one `EvidenceRecord` per file**
  (not per-line, unlike every prior parser in this package), carrying the
  full decoded source text: AST parsing needs a file's whole text as one
  syntactic unit. `sniff()` recognizes Python/JavaScript/TypeScript/Java
  content shapes; claims `.py`/`.pyw`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.ts`/
  `.tsx`/`.java` extensions, registered in `core/parsers/registry.py` at
  priority 3. `evidence_allowed_extensions` (settings + `.env.example`)
  gained all nine source extensions — realistically uploaded with their
  real extensions, unlike the `.txt`-fallback precedent ADR-0019/0020 used.
- **`core/services/owasp_security_service.py`** (new) —
  `assess_source_code()`, synchronous (**no DB session parameter** — this
  framework never persists), composing `SourceCodeAnalysisEngine`
  end-to-end and emitting audit events. Gets the documented
  dependency-rules exception 4i (mirrors 4g/4h, minus the `core/memory`
  edge those have).
- **`core/tools/owasp_tools.py`** (`OwaspSecurityAssessmentTool`, new) —
  blueprint's exact named file. Aggregates already-computed SAST findings
  into a case-level summary (counts by OWASP category/CWE/severity, top-N);
  never recomputes a severity/confidence/risk score itself.
- **`core/agents/owasp_security_agent.py`** (`OwaspSecurityAgent`,
  `SastAdvice`, new) — the seventh concrete specialist agent, capability
  `owasp_source_code_review`. Deliberately thin: reads
  `CaseInvestigationState.owasp_security_records` (new state field, plain
  `dict[str, object]` entries — a distinct field name from every other
  `*_records` field) and calls `OwaspSecurityAssessmentTool` to produce a
  case-level `SastAdvice`. `core/agents` has no dependency-rules.md import
  edge onto `core/owasp_security` (identical reasoning to every other
  specialist agent's precedent).
- **`core/graph/investigation_graph.py`** (modified) — `OwaspSecurityAgent`
  registered/wired with the same two-line pattern the other six
  specialists established; module docstring updated to describe seven
  agents and to note M4 is now fully closed.
- **`core/graph/state.py`** (modified) — `CaseInvestigationState` gained
  `owasp_security_records: list[Any]` (same `operator.add` reducer shape).
- **`core/services/case_service.py`** (modified) —
  `_EVIDENCE_TYPE_CAPABILITIES` gained `SOURCE_CODE` ->
  `owasp_source_code_review`; new `_OWASP_SECURITY_EVIDENCE_TYPES` gating
  set; `_run_specialist_agents` registers the seventh agent and hydrates
  `owasp_security_records`; `investigate_new_evidence()` conditionally
  calls `assess_source_code()` (gated to `SOURCE_CODE` only, synchronous,
  no session) and reduces its already-generated `SastAdvice` (findings +
  summary) into plain-dict records before hydrating state, recording a
  `TimelineEvent(SAST_ASSESSED)`. `CaseInvestigationResult` gained
  `sast_finding_count`/`highest_sast_risk_level`; new
  `_extract_owasp_security` mirrors `_extract_web_security`.
- **`core/db/models/timeline_event.py`** (modified) — new
  `TimelineEventType.SAST_ASSESSED` + one new Alembic migration
  (`27d5a3474dca`) additively extending `timeline_event_type_enum`.
- **`apps/api/schemas.py`/`routers/evidence.py`** (modified) —
  `EvidenceUploadResponse` gained `sast_finding_count`/
  `highest_sast_risk_level` (both `None`-defaulted, purely additive).
- **`core/config/settings.py`/`.env.example`** (modified) — every
  configurable threshold/weight this framework uses (max lines/chars per
  artifact, the five risk-assessment weights), plus the nine new
  source-code extensions added to `evidence_allowed_extensions` — zero
  hardcoded values anywhere in `core/owasp_security`.
- **`data/sample_evidence/{vulnerable_app.py,safe_app.py,vulnerable_app.js,
  VulnerableApp.java}`** (new fixtures) — a deliberately vulnerable Python
  module (command injection, hardcoded secret, SQL injection, weak
  cryptography, insecure randomness, unsafe deserialization, path
  traversal, broken authentication, open redirect, sensitive information
  exposure, insecure configuration — eleven of fifteen categories in one
  file), a deliberately clean Python module (false-positive-reduction
  fixture — SHA-256 for a cache key, `secrets.token_urlsafe`, a
  constant-path `open()`), and small vulnerable JavaScript/Java snippets
  exercising the pattern-based path.
- **Testing** — 138 new tests: unit tests for every `core/owasp_security`
  module (models, rule_engine including the new `ast_predicate` kind,
  language_detector, python_ast_analyzer — all fifteen categories
  individually plus malformed-source handling, pattern_analyzer — JS/TS/
  Java coverage plus a cross-language-rule-isolation test,
  vulnerability_detection_engine, secure_coding_advisor, evidence_mapper,
  confidence_calculator, finding_generator, risk_assessment,
  analysis_engine — oversized-input guards, graceful degradation, and a
  named regression test for a real bug caught during manual smoke-testing
  (see Key Decisions), metrics, audit), the new parser (including registry
  priority/sniff behavior), the tool, the agent, integration tests proving
  the vulnerable/safe/JS/Java fixtures are detected (or correctly *not*
  detected) end-to-end, a 2,000-function synthetic-file performance test
  plus an instantaneous-rejection test for the oversized-input guard, and
  an API `TestClient` test proving this evidence type routes to
  `OwaspSecurityAgent` through the real pipeline. `test_investigation_graph.py`'s
  node-set assertion extended to the seventh agent;
  `test_parsers_registry.py`'s builtin-parser-count assertion extended to
  seventeen. Full pytest suite (1533 tests, up from 1395), `ruff check`/
  `format --check`, and `scripts/check_dependency_rules.py` all pass.
  `core/owasp_security`/`core/owasp_web` (and every file touched this
  session) are individually `mypy --strict` clean; a whole-repo
  `mypy core --strict` run still cannot complete due to a pre-existing,
  unrelated numpy/pandas stub incompatibility (see Known Issues,
  unchanged from last session).

**Explicitly NOT built, by ADR-0021's stated scope:** Penetration testing,
active vulnerability scanning, incident response, threat hunting, MITRE
ATT&CK mapping, automated exploitation, or LLM reasoning of any kind
anywhere in this package; a concrete `OwaspSecurityEnrichmentProvider`-style
seam (deliberately absent, matching `core.owasp_web`/`core.linux_advisor`'s
precedent); DB persistence of any kind; a real JavaScript/TypeScript/Java
AST parser (deliberately deferred to a future ADR that would add the
needed dependency); any redesign of `SocAnalystAgent`, `PhishingAgent`,
`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`, `LinuxSecurityAgent`,
`WebSecurityAgent`, `Case`, or any prior framework — only extended.

---

## Repository Status

```
apps/
  api/            schemas.py (MODIFIED: +2 IR response fields, +2 MITRE
                   fields/+2 SAST fields earlier) + routers/{system,cases,
                   evidence(MODIFIED: passes through IR + MITRE + SAST
                   fields),iocs,findings,v1}.py                          [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (unchanged this session)                   [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py,
                   vulnerability_agent.py, threat_hunter_agent.py,
                   linux_security_agent.py, web_security_agent.py,
                   owasp_security_agent.py, mitre_mapping_agent.py
                   (unchanged) + incident_response_agent.py (NEW — ninth
                   concrete specialist agent — half-closes M5)           [implemented — 9 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py, vuln_tools.py,
                   linux_security_tools.py, linux_tools.py,
                   web_security_tools.py, owasp_tools.py, mitre_tools.py
                   (unchanged) + ir_tools.py (NEW —
                   IncidentResponsePlanGenerationTool, blueprint's exact
                   named file)                                           [implemented — 9 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged)                  [implemented]
  graph/          investigation_graph.py (MODIFIED: +IncidentResponseAgent
                   wiring) + state.py (MODIFIED:
                   +incident_response_finding_records field) +
                   routing.py/workflow_engine.py/events.py/retry.py/
                   failure_recovery.py/metrics.py (unchanged)             [implemented]
  db/             MODIFIED: +incident_response_plan.py
                   (IncidentResponsePlanRow) +
                   incident_response_plan_repository.py (NEW) + two new
                   Alembic migrations                                    [implemented — 12 real domain tables + 5 reference tables]
  parsers/        (unchanged this session)                               [implemented — 17 concrete parsers]
  incident_response/ (NEW — this session's leaf package: models.py,
                   exceptions.py, inputs.py, severity_classifier.py,
                   playbook_rules.py, risk_prioritizer.py,
                   action_ordering.py, confidence_calculator.py,
                   response_plan_engine.py, metrics.py, audit.py)        [implemented]
  owasp_security/ (unchanged)                                             [implemented]
  owasp_web/      (unchanged)                                             [implemented]
  linux_advisor/  (unchanged — ADR-0019's separate framework)             [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged — this session's agent/tool never touch
                   this package)                                         [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +incident_response_synthesis
                   capability routing (every evidence type),
                   +_hydrate_incident_response_records,
                   +_persist_incident_response_plan) + finding_service.py
                   (unchanged) + evidence_service.py, threat_intel_service.py,
                   vulnerability_service.py, linux_security_service.py,
                   linux_advisor_service.py, web_security_service.py,
                   owasp_security_service.py (unchanged); report_service.py [implemented]
data/             (unchanged this session)
scripts/          (unchanged)
tests/
  unit/           213 test modules (+11 this session:
                   test_incident_response_{models,severity_classifier,
                   playbook_rules,risk_prioritizer,action_ordering,
                   confidence_calculator,response_plan_engine}.py,
                   test_tools_ir_tools.py,
                   test_agents_incident_response_agent.py,
                   test_db_incident_response_plan_repository.py)
  integration:    16 test modules (+0 new files this session; +2 extended:
                   test_case_service_pipeline.py [incident_response_
                   recommendation_count assertion + new timeline event
                   type on the SSH-auth-log test],
                   test_investigation_graph.py [node-set assertion
                   extended to the ninth agent])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs + docs/adr/ (24 ADR files incl.
                   template, +0023) + docs/dependency-rules.md (MODIFIED:
                   +rule 5b, `core/tools/ir_tools.py`'s
                   `core/incident_response` exception) + docs/diagrams/
                   (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1604 tests passing as of this session (1546 prior -> 1604 now: 58 new [some
prior counts undercounted files vs. individual tests — see git log for the
exact per-commit delta]).
Modified this session: `core/graph/{state,investigation_graph}.py`,
`core/services/case_service.py`, `core/db/models/__init__.py`,
`core/db/models/timeline_event.py`, `apps/api/{schemas,routers/evidence}.py`,
`docs/{roadmap,dependency-rules}.md`, `core/{agents,tools}/README.md`,
`tests/integration/{test_case_service_pipeline,test_investigation_graph}.py`,
`CHANGELOG.md`, and this file. New: `docs/adr/0023-incident-response-agent.md`,
`core/incident_response/*.py` (11 files + README), `core/tools/ir_tools.py`,
`core/agents/incident_response_agent.py`,
`core/db/models/incident_response_plan.py`,
`core/db/incident_response_plan_repository.py`, two new Alembic migrations
(`f3a9c1d7e2b5`, `b7e4d2f8a1c9`), 11 new test files — all currently
uncommitted until this session's commit (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extended (not reversed) by
ADR-0001 through ADR-0023. **M2 and M4 are both fully closed; M5 is half
closed** (Incident Response Agent done, Report Generator Agent open). This
session's deliberate decisions, documented in
`docs/adr/0023-incident-response-agent.md`:

1. **A real execution-semantics conflict was surfaced and resolved before
   writing any code** — the naive "read a sibling agent's `agent_outputs`
   in the same graph run" design would have silently returned empty results
   every time, per `workflow_engine.py`'s documented parallel-superstep
   isolation. Resolved by reading the same pre-hydrated input `*_records`
   fields every other specialist already reads, plus one new case-wide
   `incident_response_finding_records` field mirroring
   `mitre_mapping_records`'s pattern — never sibling `agent_outputs`.
2. **`core/incident_response/` is a new leaf package; only
   `core/tools/ir_tools.py` (not the agent) gets a new dependency-rules.md
   exception (rule 5b) to import it directly** — mirroring
   `core/tools/mitre_tools.py`'s existing `core/knowledge` exception
   exactly; the agent itself needs no new exception, importing only its own
   tool's typed contracts.
3. **Real DB persistence** (`incident_response_plans` table, one row per
   case, upserted) — unlike the M4 "advisory" frameworks' deliberate
   no-persistence scope, blueprint §8 literally names this table, so
   persistence was not this session's discretionary choice to skip.
4. **Cross-cutting capability routing** — `incident_response_synthesis` is
   appended to every evidence type's required-capability list, mirroring
   `mitre_technique_mapping`'s identical precedent.
5. **An honest, disclosed scope limitation, not a hidden one** — this
   agent's cross-upload continuity is strongest for SOC/Threat-Hunting/
   Phishing/MITRE-derived signal (the only subsystems whose output reaches
   the persisted `Finding` table today); Vulnerability/Linux/OWASP/Web
   signal is only available for the single evidence upload currently being
   processed. Closing that gap would mean redesigning five already-shipped
   frameworks — explicitly out of scope, flagged for a future session
   instead of silently narrowed.

---

### M2's MITRE Mapping Agent architecture decisions (prior session, unchanged)

1. **The pre-implementation conflict was surfaced, not silently resolved
   either way** — the task asked for a full new mapping-engine framework;
   this session found `core/findings/`/`core/knowledge/mitre/` already
   implemented nearly all of it (ADR-0013) and stopped to ask the user
   before writing any code, rather than either duplicating the engine or
   unilaterally deciding to skip the task's request.
2. **`core/tools/mitre_tools.py` wraps `MitreLookup`, never
   `MitreMappingEngine`** — technique/confidence mapping stays exactly
   where ADR-0013 put it; this tool only resolves already-mapped
   technique IDs to tactic/group/software/mitigation metadata.
3. **`core/agents/mitre_mapping_agent.py` is the one agent in this
   codebase permitted to import `core.knowledge.mitre` directly**
   (docs/dependency-rules.md rule 4/4c) — a documented, pre-existing
   exception the dependency rules already anticipated for exactly this
   agent, not a new rule written to accommodate it.
4. **Cross-cutting capability routing** — `mitre_technique_mapping` is
   appended to every evidence type's required-capability list, the first
   capability in this codebase that isn't evidence-type-gated.
5. **No second mapping engine, confidence calculator, metrics collector,
   audit module, evidence aggregator, or deduplication engine** — all
   reused as-is from `core/findings/`.
6. **`_hydrate_mitre_mapping_records` reads `json.loads(Finding.
   finding_data_json)` directly**, never importing
   `core.findings.models.FindingRecord` into `case_service.py` (that
   import edge stays scoped to `finding_service.py`, rule 4c).
7. **Scoped to the whole case, not just the triggering upload** — matches
   blueprint §13's MITRE ATT&CK heatmap, which is inherently case-wide.
8. **A known, accepted minor inefficiency**: a second `MitreLookup` is
   built per investigation run (one inside `finding_service.
   FindingGenerationPipeline`, one inside this agent's tool registry) —
   both load the same small, local, vendored JSON file deterministically;
   not optimized this session, flagged for later if profiling ever shows
   it matters.

---

### M4's OWASP Security Agent (prior session, unchanged)

**M4 is fully closed** — every blueprint-named specialist agent for this
milestone exists. Fifteen deliberate decisions, all documented in
`docs/adr/0021-owasp-security-agent-ast-sast.md`:

1. **`core/owasp_security/` is a new, deliberately distinct package from
   `core/owasp_web/`** (ADR-0020) — different input (source code vs. HTTP
   traffic), different agent/tool/state-field names, never imports each
   other.
2. **New `EvidenceType.SOURCE_CODE`** — purely additive.
3. **New parser `SourceCodeParser`** — deliberately **one record per file**
   (not per-line, the only parser in this codebase shaped this way), since
   AST parsing needs the whole file as one syntactic unit.
4. **No DB persistence, no enrichment-provider seam** — matching
   `core/linux_advisor`/`core/owasp_web`'s precedent exactly.
5. **`SastSeverity`/`OwaspCategory` are this package's own enums** — never
   a reuse of a sibling leaf's, even though `OwaspCategory`'s *values*
   overlap conceptually with `core.owasp_web.models.OwaspCategory`.
6. **A fifteen-category `VulnerabilityCategory` enum**, each mapped to one
   `OwaspCategory` and one representative CWE id via static lookup tables
   — the single source of truth for that mapping.
7. **One generic `Rule`/`RuleEngine` supports both text and AST matching**
   via a four-kind tagged union (`regex`/`literal_substring`/
   `callable_signature`/`ast_predicate`) — composable, versioned,
   prioritized, enable/disable-capable, satisfying every property the task
   named for the "Rule Engine."
8. **Python gets genuine AST analysis (stdlib `ast`, zero new
   dependencies); JavaScript/TypeScript/Java get pattern-based analysis**
   — an explicit, ADR-documented scope boundary (no AST library exists in
   this repo for those languages, and adding one wasn't justified by this
   task alone), not a hidden shortcut. `confidence_calculator.py` makes the
   reliability difference structurally visible.
9. **`python_ast_rules.py`'s predicates are heuristic, not full taint
   tracking** — every predicate's docstring states its detection basis and
   known false-positive shape explicitly.
10. **`secure_coding_advisor.py` distinguishes finding-triggered from
    baseline recommendations**, mirroring `hardening_advisor.py`'s
    established shape exactly.
11. **`evidence_mapper.py` and `confidence_calculator.py` are the task's
    named "Evidence Mapping" and "Confidence Calculator" capabilities** as
    dedicated, single-responsibility modules — not folded into
    `finding_generator.py`.
12. **Config-driven, no-hardcoded-values scoring** — five configurable
    dimensions, read from `Settings`, validated to sum to 1.0.
13. **`analysis_engine.py` defends against four failure classes** without
    ever aborting the whole artifact: oversized input, an unsupported/
    undetected language, a genuine Python syntax error, and log-injection-
    shaped content — the last one discovered mid-session to require
    per-snippet (never whole-file) sanitization (see Key Decisions).
14. **`owasp_tools.py`/`owasp_security_agent.py` never recompute a risk/
    confidence score** — `core/agents` has no import edge onto
    `core/owasp_security`, so state stays plain-dict-typed.
15. **No penetration testing, active scanning, incident response, threat
    hunting, MITRE mapping, automated exploitation, or LLM reasoning
    anywhere in this package; the package never executes/`eval`s/runs any
    analyzed source code.**

`docs/roadmap.md` records both M2 and M4 as **checked off** (`- [x]`), each
with a dated addendum explaining why. No approved architectural decision
(ADR-0001 through 0021) was reversed by this session.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session (Incident Response Agent, ADR-0023):**

- **A real execution-semantics conflict was surfaced before writing any
  code, not discovered mid-implementation** — read
  `core/graph/workflow_engine.py::_make_node`'s docstring, confirmed by
  `core/agents/planning_agent.py` (every `PlannedStep.depends_on` is empty)
  and `core/graph/routing.py` (only fans out to entry steps): sibling nodes
  in the same LangGraph superstep never see each other's writes. The naive
  "read `state.agent_outputs[sibling.name]`" design was ruled out before any
  file was written, in favor of reading pre-hydrated input `*_records`
  fields (populated before the graph runs, not during it) plus one new
  case-wide field mirroring `mitre_mapping_records`.
- **Persistence was not a discretionary "skip it like the M4 advisory
  frameworks did" choice** — blueprint §8's DB design literally names
  `Case ├─ 1 IncidentResponsePlan (nullable)`, and the task brief's own
  pipeline names "Persist Response Plan" as a stage. Checked both documents
  before deciding to build `incident_response_plans` for real, unlike
  `SastAdvice`/`WebSecurityAdvice`/`LinuxSecurityAdvice`.
- **The DB ORM class is named `IncidentResponsePlanRow`, not
  `IncidentResponsePlan`** — grepped for the existing
  `LinuxSecurityFindingRow` precedent before naming it, to avoid a same-name
  collision with the Pydantic model in `core/incident_response/models.py`.
- **`core/services/case_service.py` needed zero new import edges** —
  `IncidentResponsePlanRepository.upsert_for_case` takes the plan as a plain
  `dict[str, object]` (not the typed Pydantic model) specifically so
  `case_service.py` never has to import `core/incident_response` itself;
  the Pydantic model stays imported only inside `core/db`, matching
  `core/db/models/finding.py`'s existing "leaf imports a sibling leaf's
  model for column typing" precedent.
- **A real, defensible ATT&CK tactic-ID -> `ResponseCategory` mapping
  table** (`playbook_rules.py::_TACTIC_CATEGORY_MAP`) covers all fourteen
  MITRE ATT&CK Enterprise tactics (`TA0001`-`TA0011`, `TA0040`, `TA0042`,
  `TA0043`) — real, stable ATT&CK IDs, not invented ones — each mapped to
  one or more of the task's eleven named response categories, with a
  keyword fallback and a severity-only last resort, in that fixed
  precedence order, so a finding with no MITRE mapping at all (e.g. a
  Linux Advisor or OWASP Web finding) still earns at least evidence
  preservation.
- **The plan-level confidence rollup is discounted by the fraction of
  skipped/malformed input records** (`confidence_calculator.py`) — a plan
  built from a case where several finding records could not be parsed is
  genuinely less trustworthy, and that had to be visible in the number
  itself, not just a log line.

---

**New in the prior session (MITRE Mapping Agent, ADR-0022):**

- **A real conflict was raised before writing any code** — the task brief's
  requested "MITRE Mapping framework" (Mapping Engine, Confidence
  Calculator, Metrics, Audit Events, evidence aggregation, dedup,
  persistence) almost entirely duplicated `core/findings/`
  (`MitreMappingEngine`, `ConfidenceEngine`, `dedup.py`,
  `evidence_aggregation.py`, `metrics.py`, `audit.py`) and
  `core/knowledge/mitre/lookup.py` (`MitreLookup`'s already-existing
  `tactics_for_technique`/`groups_using_technique`/
  `software_using_technique`/`mitigations_for_technique`), all already
  wired into production via `finding_service.py`/`case_service.py` since
  ADR-0013. Presented to the user as an explicit choice (rebuild the
  duplicate framework vs. a thin agent+tool extending the existing engine)
  via `AskUserQuestion` before any file was written; the user chose the
  thin extension.
- **`MitreLookup.groups_using_technique`/`software_using_technique` had
  zero callers anywhere in the codebase before this session** — confirmed
  by grep before writing `mitre_tools.py`; this session is the first to
  actually use them.
- **Sub-technique resolution needed no new data** — ATT&CK's own
  `"T1110.001"` ID convention (a literal `"."`) is sufficient to derive a
  sub-technique's parent ID; no separate parent/child relationship data
  exists in, or was added to, the vendored dataset.
- **`build_investigation_graph()` gained a `settings: Settings | None`
  parameter, defaulting to `Settings()` when omitted** — every other
  existing caller (all in `tests/integration/test_investigation_graph.py`)
  needed no change, since every `Settings` field has a default and the
  vendored MITRE bundle loads from its default path.
- **A second `MitreLookup` load per investigation run was accepted, not
  optimized away** — no existing seam lets
  `core/agents/mitre_mapping_agent.py`'s tool registry reuse the
  `MitreLookup` `finding_service.FindingGenerationPipeline` already built
  internally for the same request, and building that seam wasn't
  justified by this task alone (small, local, deterministic file read;
  flagged in the ADR for a future session if profiling ever shows it
  matters).

---

**New in the prior session (OWASP Security Agent, ADR-0021):**

- **No conflict to raise that session** — unlike the session before it
  (which had to reconcile a task brief against a different blueprint
  definition), that task matched blueprint §7's OWASP Security Agent
  exactly. The only
  pre-implementation check needed was confirming zero overlap with
  ADR-0020's `core/owasp_web`, which the task itself explicitly required.
- **No new third-party dependency for JavaScript/TypeScript/Java AST
  parsing** — checked `requirements.txt` before writing any code; none of
  `esprima`/`tree-sitter`/`javalang` (or equivalents) exist. Rather than
  add one unilaterally, this session built the honest pattern-based
  fallback and documented the boundary in ADR-0021, leaving a real
  extension seam (a new `LanguageAnalyzer`-shaped class + a routing entry)
  for a future session to upgrade behind its own ADR.
- **A real bug caught by manual smoke-testing, not by a written test**:
  the first draft of `analysis_engine.py` ran the same `sanitize_text`
  helper `core.owasp_web.advisory_engine` uses (designed for single HTTP-
  transcript lines) over the **entire multi-line source file** before AST
  parsing. Since that sanitizer collapses every newline to a single space,
  it turned every multi-line Python file into one syntactically-invalid
  line, and `SourceCodeAnalysisEngine.analyze()` silently degraded every
  real file to "could not be parsed" — caught only by running a crafted
  vulnerable snippet through the pipeline by hand before writing any
  tests. Fixed by moving sanitization to a new `text_utils.sanitize_snippet`
  helper applied only to short, already-extracted per-finding code
  snippets (in `python_ast_analyzer.py`/`pattern_analyzer.py`), never to
  the whole source text. A named regression test
  (`test_vulnerable_multiline_python_file_produces_findings`) now guards
  this specifically.
- **`owasp_security_records` is a new, separate `CaseInvestigationState`
  field**, never reusing any prior `*_records` field.
- **Two latent, pre-existing `mypy --strict` issues in `core/owasp_web`
  were found and fixed while verifying this session's work** (not
  introduced this session, but cheap and correct to fix alongside):
  `header_rules.py`/`misconfig_rules.py` passed bare string literals
  (`kind="regex"`) where `Matcher.kind` is typed as the `MatcherKind` enum
  (works fine at runtime via Pydantic's `StrEnum` coercion, but fails
  `mypy --strict`'s static check); `advisory_engine.py` reused one loop
  variable name (`finding`) across three mutually-incompatible finding
  types in sibling `if`/`elif`-shaped branches within the same loop body.
  Both fixed with zero behavior change (pure type-annotation/naming
  fixes); the full test suite was re-run clean afterward.

---

## Public Interfaces

*(M0–M4/ADR-0015–0022 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session (Incident Response Agent, ADR-0023):**

`core.incident_response.models.{IncidentSeverity, severity_rank,
highest_severity, ResponsePriority, priority_rank, ResponseCategory,
ResponsePhase, ResponseTimeframe, ResponseEvidence, ResponseAction,
ResponseRecommendation, ResponseMetrics, IncidentResponsePlan}` (new).

`core.incident_response.inputs.IncidentInputFinding` (new).

`core.incident_response.exceptions.{IncidentResponseError,
InvalidFindingInputError, OversizedFindingSetError}` (new).

`core.incident_response.severity_classifier.{IncidentSeverityClassifier,
SeverityClassificationWeights}` (new).

`core.incident_response.playbook_rules.{CategoryTemplate,
CATEGORY_TEMPLATES, match_categories, build_action}` (new).

`core.incident_response.risk_prioritizer.{RiskPrioritizer,
PrioritizationWeights}` (new).

`core.incident_response.action_ordering.order_recommendations` (new).

`core.incident_response.confidence_calculator.{calculate_plan_confidence,
calculate_plan_risk_score}` (new).

`core.incident_response.response_plan_engine.ResponsePlanEngine` (new).

`core.incident_response.metrics.{IncidentResponseMetricsCollector,
IncidentResponseMetricsSnapshot}` (new).

`core.incident_response.audit.{AuditAction,
log_incident_response_audit_event, timed_execution}` (new).

`core.tools.ir_tools.{IncidentResponsePlanGenerationTool,
IncidentResponsePlanGenerationInput, IncidentResponsePlanGenerationOutput,
DEFAULT_MAX_FINDINGS_PER_PLAN}` (new).

`core.agents.incident_response_agent.{IncidentResponseAgent,
default_incident_response_agent_tool_registry, IncidentResponseAgentResult}`
(new).

`core.db.models.incident_response_plan.IncidentResponsePlanRow` (new).

`core.db.incident_response_plan_repository.IncidentResponsePlanRepository`
(new).

`core.db.models.timeline_event.TimelineEventType.
INCIDENT_RESPONSE_PLAN_GENERATED` (new).

`core.graph.state.CaseInvestigationState.incident_response_finding_records`
(new field). `core.graph.investigation_graph.build_investigation_graph` now
also registers/wires `IncidentResponseAgent` (node name
`incident_response_agent`).

`core.services.case_service`: new `_hydrate_incident_response_records`,
`_persist_incident_response_plan`; `_required_capabilities_for` now appends
`incident_response_synthesis` to every evidence type; `_run_specialist_agents`
registers a ninth agent. `CaseInvestigationResult` gained
`incident_response_recommendation_count`/`incident_severity`.

`apps.api.schemas.EvidenceUploadResponse` gained
`incident_response_recommendation_count`/`incident_severity` (both
optional, default `None`).

No Report Generator Agent, LLM reasoning, `/api/v1/reports` route, or
`core.security.{pii_redaction,approval_gate}` implementation exist as
public interfaces yet.

---

**New/changed in the prior session (MITRE Mapping Agent, ADR-0022):**

`core.tools.mitre_tools.{MitreMappingResolutionTool,
MitreTechniqueMappingInput, MitreCaseMappingInput, MitreTechniqueResolution,
MitreCaseMappingOutput, parent_technique_id, DEFAULT_TOP_N}` (new).

`core.agents.mitre_mapping_agent.{MitreMappingAgent,
default_mitre_mapping_agent_tool_registry, MitreCaseMappingSummary,
MitreMappingAgentResult}` (new).

`core.graph.state.CaseInvestigationState.mitre_mapping_records` (new
field). `core.graph.investigation_graph.build_investigation_graph` gained
a `settings: Settings | None = None` parameter and now also registers/
wires `MitreMappingAgent` (node name `mitre_mapping_agent`).

`core.services.case_service`: new `_hydrate_mitre_mapping_records`;
`_required_capabilities_for` now appends `mitre_technique_mapping` to
every evidence type; `_run_specialist_agents` gained a `settings`
parameter and registers an eighth agent; new `_extract_mitre_mapping`.
`CaseInvestigationResult` gained `mitre_technique_count`/
`mitre_distinct_group_count`.

`apps.api.schemas.EvidenceUploadResponse` gained `mitre_technique_count`/
`mitre_distinct_group_count` (both optional, default `None`).

**New/changed in the prior session (OWASP Security Agent, ADR-0021):**

`core.owasp_security.*` (new package) —
`models.{SourceLanguage, AST_SUPPORTED_LANGUAGES, SastSeverity,
severity_rank, highest_severity, OwaspCategory, VulnerabilityCategory,
CATEGORY_OWASP_MAP, CATEGORY_CWE_MAP, MatcherKind, RulePriority, RuleMatch,
SourceFinding, SecureCodingRecommendation, SastFinding, SastAdvice,
RiskDimensionScores}`,
`exceptions.{SastError, UnsupportedLanguageError, AstParseError,
OversizedSourceInputError}`,
`language_detector.LanguageDetector`,
`rule_engine.{Matcher, Rule, RuleEngine, register_callable,
register_ast_predicate}`,
`python_ast_rules.DEFAULT_PYTHON_AST_RULES` (+ fifteen registered named
predicates),
`pattern_rules.DEFAULT_PATTERN_RULES`,
`python_ast_analyzer.{PythonAstAnalyzer, build_ast}`,
`pattern_analyzer.PatternSourceAnalyzer`,
`vulnerability_detection_engine.VulnerabilityDetectionEngine`,
`secure_coding_advisor.SecureCodingAdvisor`,
`evidence_mapper.map_evidence_reference`,
`confidence_calculator.{calculate_confidence, AST_BASED_MULTIPLIER,
PATTERN_BASED_MULTIPLIER}`,
`finding_generator.FindingGenerator`,
`risk_assessment.{RiskAssessmentEngine, SastRiskWeights}`,
`text_utils.sanitize_snippet`,
`analysis_engine.{SourceCodeAnalysisEngine, sanitize_text}`,
`metrics.{SastMetricsCollector, SastMetricsSnapshot}`,
`audit.{AuditAction, log_sast_audit_event, timed_execution}`.

`core.parsers.models.EvidenceType.SOURCE_CODE` (new).
`core.parsers.source_code_parser.SourceCodeParser` (new).

`core.db.models.timeline_event.TimelineEventType.SAST_ASSESSED` (new).

`core.services.owasp_security_service.{assess_source_code,
SastAssessmentResult, build_source_code_analysis_engine}` (new).

`core.tools.owasp_tools.{OwaspSecurityAssessmentTool,
OwaspSecurityAssessmentInput, OwaspSecurityAssessmentOutput,
SastFindingSummaryInput}` (new).

`core.agents.owasp_security_agent.{OwaspSecurityAgent,
default_owasp_security_agent_tool_registry, SastAdvice,
OwaspSecurityAgentResult}` (new).

`core.graph.state.CaseInvestigationState.owasp_security_records` (new
field). `core.graph.investigation_graph.build_investigation_graph` now
also registers/wires `OwaspSecurityAgent` (node name
`owasp_security_agent`).

`core.services.case_service`: `_EVIDENCE_TYPE_CAPABILITIES` gained
`SOURCE_CODE -> owasp_source_code_review`; `_run_specialist_agents` gained
`owasp_security_records` parameter and registers a seventh agent; new
`_extract_owasp_security`. `CaseInvestigationResult` gained
`sast_finding_count`/`highest_sast_risk_level`.

`apps.api.schemas.EvidenceUploadResponse` gained `sast_finding_count`/
`highest_sast_risk_level` (both optional, default `None`).

`core.config.Settings` gained 7 new fields:
`owasp_security_max_lines_per_artifact`,
`owasp_security_max_chars_per_artifact`, five
`owasp_security_risk_weight_*` fields; `evidence_allowed_extensions`
default gained `.py,.pyw,.js,.jsx,.mjs,.cjs,.ts,.tsx,.java`.

No Incident Response Agent, Report Generator Agent, LLM reasoning,
`/api/v1/reports` route, or `core.security.{pii_redaction,approval_gate}`
implementation exist as public interfaces yet.

---

## Remaining Work

1. **M2 — closed** (prior session). `core/agents/mitre_mapping_agent.py` +
   `core/tools/mitre_tools.py` wrap `core.knowledge.mitre`'s lookup engine
   and `core.findings`'s existing mapping engine (ADR-0022).
2. **M3 — closed** (prior session).
3. **M4 — closed** (prior session). All five specialist-agent pieces
   (Vulnerability Assessment, Threat Hunting, Linux Security Advisor, the
   out-of-blueprint Web Security Agent, and the AST-based OWASP Security
   Agent) are built.
4. **M5 — half closed this session.** The Incident Response Agent half is
   done (`core/incident_response/`, `core/tools/ir_tools.py`,
   `core/agents/incident_response_agent.py`, real DB persistence — ADR-0023).
   **Still open:** the Report Generator Agent, Jinja2/ReportLab templates
   per module + case-level executive report, Plotly chart generation, and
   the `/api/v1/reports` route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB,
   populate remaining knowledge data (playbooks), the real cross-evidence
   Threat Timeline UI feature, MITRE heatmap/AI Analyst Chat UI.
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** `core/security/pii_redaction.py`/
   `approval_gate.py`; a structured read endpoint for `Case.labels`; a
   concrete `LinuxSecurityEnrichmentProvider`/`VulnerabilityEnrichmentProvider`/
   `WebSecurityEnrichmentProvider`/`OwaspSecurityEnrichmentProvider` (e.g. a
   live CVE/NVD lookup — `core/owasp_security` has no such seam at all, by
   design); a real JavaScript/TypeScript/Java AST parser (would need a new
   dependency + its own ADR); CVSS v4.0 base-score computation; a real
   journald-field mapping in `core/parsers/field_heuristics.py`;
   reconciling `SocFinding`/`PhishingVerdict`/`VulnerabilityFinding`/
   `LinuxSecurityFinding`/`LinuxSecurityAdvice`/`WebSecurityAdvice`/
   `SastAdvice` (all in-memory only) with the persisted `Finding` table
   into one shared representation (this is now also what would strengthen
   `IncidentResponseAgent`'s cross-upload continuity for those four
   subsystems — see ADR-0023 Decision 1); an asset-criticality inventory;
   an "analyst requests it" on-demand incident-response-plan regeneration
   API route (today the plan only regenerates on the next evidence upload).

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist;
`apps/web` has no code; harmless Starlette deprecation warnings in test
output; no CI has ever actually run on GitHub;
`scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import
rule, not the full sibling-layer matrix; `InMemoryVectorStore` is O(n)
brute-force; `HashingTextEmbedder` is not semantic;
`windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`;
`SocAnalystAgent`'s/`PhishingAgent`'s/`VulnerabilityAssessmentAgent`'s/
`ThreatHunterAgent`'s finding output is still not persisted to the
`findings` table; `Report` still has no consumer; on PostgreSQL,
downgrading the `CaseStatus`/`timeline_event_type` enum-extension
migrations is a no-op; `Case.labels` has no read endpoint; no case-level
authorization/ownership check; the duplicate-case guard is intentionally
narrow; CVSS v4.0 is vector-validation-only; multi-CVE scan findings fold to
their first CVE; no asset-criticality inventory exists.)*

- **Still open — `mypy core --strict` (whole-repo) cannot run to
  completion.** Unchanged from last session:
  `numpy/__init__.pyi:737: error: Type statement is only supported in
  Python 3.12 and greater [syntax]`, a pre-existing environment
  incompatibility (numpy's inline stubs use PEP 695 syntax, pulled in
  transitively via `pandas` — used by CSV parsers — while
  `pyproject.toml`'s `python_version = "3.11"` rejects that syntax), not
  caused by any session's changes. This session additionally verified:
  every file in `core/incident_response` (and every other file touched
  this session) passes `mypy --strict` cleanly when checked directly
  (bypassing the numpy-pulling files, e.g. `investigation_graph.py`/
  `case_service.py`, which transitively import pandas-based parsers).
  Resolving the numpy/mypy/Python-version mismatch itself (pin an older
  numpy, or bump the mypy `python_version`) remains environment
  maintenance outside any single feature session's scope.
- **`IncidentResponseAgent`'s cross-upload continuity is uneven across
  subsystems, by a pre-existing, disclosed gap (not introduced this
  session)** — `VulnerabilityFinding`/`LinuxSecurityFinding`/SAST/
  `WebSecurityAdvice` findings are still not persisted to the `findings`
  table (see the next bullet), so this agent's case-wide
  `incident_response_finding_records` hydration only ever reflects SOC/
  Threat-Hunting/Phishing/MITRE-derived signal; Vulnerability/Linux/OWASP/
  Web signal is only available for the single evidence upload currently
  being processed (its pre-hydrated `*_records` field). Documented in
  ADR-0023 Decision 1, not hidden.
- **`SastAdvice`/`WebSecurityAdvice`/`LinuxSecurityAdvice` (M4 sessions'
  output types) are never persisted anywhere** — by design (ADR-0019/
  0020/0021, matching precedent), not a gap to close later on their own
  terms; the same is true of `SocFinding`/`PhishingVerdict`/
  `VulnerabilityFinding`, which *are* deferred gaps (unchanged from prior
  sessions).
- **`core/owasp_security` has no enrichment-provider seam at all** —
  matching `core/linux_advisor`/`core/owasp_web`'s precedent; no live
  CVE/NVD lookup against detected findings.
- **JavaScript/TypeScript/Java detection is pattern-based only** — no
  AST parsing for these languages in this project (documented scope
  boundary, ADR-0021); higher false-positive/false-negative rate than
  Python's AST-based detection, structurally surfaced via
  `confidence_calculator.py`'s discount rather than hidden.
- **`python_ast_rules.py`'s predicates do no data-flow/taint analysis** —
  each flags an AST shape correlated with a vulnerability category (e.g. a
  dynamically-built string passed to a sink) without proving the dynamic
  content is actually attacker-controlled; every predicate's docstring
  states this explicitly.
- **`_EVIDENCE_TYPE_CAPABILITIES` in `case_service.py` is a simple dict of
  tuples**, not a general routing engine — unchanged limitation, carried
  forward.
- **A second `MitreLookup` (and its underlying vendored-JSON parse) is
  built per investigation run** — one inside `finding_service.
  FindingGenerationPipeline`, one inside `MitreMappingAgent`'s tool
  registry (`default_mitre_mapping_agent_tool_registry`). Deterministic,
  local, offline, and cheap at current vendored-dataset size; not
  optimized (ADR-0022) — a future session could add a shared-instance seam
  if profiling ever shows it matters.
- **`MitreCaseMappingSummary` is never persisted anywhere** — by design,
  matching `SastAdvice`/`WebSecurityAdvice`/`LinuxSecurityAdvice`'s
  precedent; the underlying `Finding.mitre_mappings` data it summarizes
  *is* already persisted (ADR-0013, unchanged). **`IncidentResponsePlan`
  is the first cross-agent-synthesis output type in this codebase that
  *is* persisted** (ADR-0023 Decision 3) — a deliberate divergence from
  that precedent, justified by blueprint §8 naming the table explicitly.
- **`IncidentResponsePlanRepository.upsert_for_case` replaces the entire
  row on every regeneration** — a case with a long investigation history
  only ever has its *latest* plan queryable; no historical plan versions
  are retained (matches blueprint §8's literal "1 nullable" cardinality,
  not a bug).
- **No "analyst requests it" on-demand plan-regeneration API route exists
  yet** — the plan currently only regenerates as a side effect of the next
  evidence upload (cross-cutting routing), never on manual request outside
  that pipeline.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`core/incident_response/`, `core/tools/ir_tools.py`, and
`core/agents/incident_response_agent.py` are pure Python plus Pydantic; the
two new Alembic migrations use only SQLAlchemy already in use.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the MITRE Mapping Agent (ADR-0022) commit is
committed.

This session's Incident Response Agent work added/modified (all to be
committed in this session's single commit — see the commit hash in this
session's final report):

- New: `docs/adr/0023-incident-response-agent.md`,
  `core/incident_response/{__init__,README,models,exceptions,inputs,
  severity_classifier,playbook_rules,risk_prioritizer,action_ordering,
  confidence_calculator,response_plan_engine,metrics,audit}.{py,md}`,
  `core/tools/ir_tools.py`, `core/agents/incident_response_agent.py`,
  `core/db/models/incident_response_plan.py`,
  `core/db/incident_response_plan_repository.py`,
  `core/db/migrations/versions/{f3a9c1d7e2b5_create_incident_response_plans_table,
  b7e4d2f8a1c9_extend_timeline_event_type_for_ir}.py`,
  `tests/unit/{test_incident_response_models,
  test_incident_response_severity_classifier,
  test_incident_response_playbook_rules,
  test_incident_response_risk_prioritizer,
  test_incident_response_action_ordering,
  test_incident_response_confidence_calculator,
  test_incident_response_response_plan_engine,
  test_tools_ir_tools,test_agents_incident_response_agent,
  test_db_incident_response_plan_repository}.py`.
- Modified: `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`, `core/db/models/__init__.py`,
  `core/db/models/timeline_event.py`,
  `apps/api/{schemas,routers/evidence}.py`,
  `docs/{roadmap,dependency-rules}.md`, `core/{agents,tools}/README.md`,
  `tests/integration/{test_case_service_pipeline,test_investigation_graph}.py`,
  `CHANGELOG.md`, this file.

Full suite (1604 tests), `ruff check`/`format --check`, and
`scripts/check_dependency_rules.py` all pass. `mypy core --strict`
(whole-repo) fails on the same pre-existing, unrelated numpy/environment
issue as prior sessions (see Known Issues); every file this session
touched is individually `mypy --strict` clean.

---

## Next Recommended Prompt

> M2, M3, and M4 are fully closed; M5 is now half closed — the Incident
> Response Agent (`core/incident_response/`, `core/tools/ir_tools.py`,
> `core/agents/incident_response_agent.py`, ADR-0023) is built, tested, and
> persisted. Begin the second M5 half next: the **Report Generator Agent**
> — Jinja2/ReportLab templates per module + a case-level executive report,
> Plotly chart generation, and the `/api/v1/reports` route. It now has nine
> specialist agents' worth of findings (including a real, persisted
> `IncidentResponsePlan`) to render into a report — this is the natural,
> intended consumer of everything built so far. Preserve every existing
> file and architectural decision described in this document — including
> all nine specialist agents (the newest, `IncidentResponseAgent`, reuses
> pre-hydrated `*_records` state fields and the case's persisted `Finding`
> rows entirely; it does not read sibling `agent_outputs` — see ADR-0023
> before assuming a "cross-agent synthesis" task needs that shape), the
> Case lifecycle subsystem, the Finding & MITRE Engine, the Vulnerability
> Assessment Framework, the Linux Security Threat Hunting Framework, the
> Linux Security Advisor Framework, the OWASP Web Security Agent Framework,
> the OWASP Security Agent (AST SAST) Framework, and the Incident Response
> Framework — only extend them. Worth considering while building the Report
> Generator: whether it should read `IncidentResponsePlanRepository`
> directly (a `core/services` -> `core/db` edge, always sanctioned) or
> through a new `core/services/incident_response_service.py`-shaped read
> function — decide and document via ADR before writing code, per the
> project's own "stop and explain before writing code" rule. Also worth
> addressing eventually (not urgent, environment-only): the pre-existing
> `mypy core --strict` failure caused by a numpy/pandas stub incompatibility
> with the pinned `python_version = "3.11"` (see this file's Known Issues)
> — either pin an older `numpy` compatible with the target Python version,
> or bump the `pyproject.toml` mypy `python_version` if the project's
> actual runtime floor has moved past 3.11.
