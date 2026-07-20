# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented blueprint §7's **MITRE Mapping Agent**
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
  api/            schemas.py (MODIFIED: +2 MITRE response fields, +2 SAST
                   response fields earlier) + routers/{system,cases,
                   evidence(MODIFIED: passes through MITRE + SAST
                   fields),iocs,findings,v1}.py                          [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (unchanged this session; +7 OWASP_SECURITY_*
                   fields + 9 evidence extensions from prior session)     [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py,
                   vulnerability_agent.py, threat_hunter_agent.py,
                   linux_security_agent.py, web_security_agent.py,
                   owasp_security_agent.py (unchanged) +
                   mitre_mapping_agent.py (NEW — eighth concrete
                   specialist agent — closes M2)                         [implemented — 8 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py, vuln_tools.py,
                   linux_security_tools.py, linux_tools.py,
                   web_security_tools.py, owasp_tools.py (unchanged) +
                   mitre_tools.py (NEW — MitreMappingResolutionTool,
                   blueprint's exact named file)                         [implemented — 8 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged — MitreLookup's
                   groups_using_technique/software_using_technique are
                   now actually called, by mitre_tools.py)                [implemented]
  graph/          investigation_graph.py (MODIFIED: +MitreMappingAgent
                   wiring, +settings parameter) + state.py (MODIFIED:
                   +mitre_mapping_records field) + routing.py/
                   workflow_engine.py/events.py/retry.py/
                   failure_recovery.py/metrics.py (unchanged)             [implemented]
  db/             (unchanged this session — MitreMappingAgent reads
                   already-persisted Finding rows, writes nothing new)   [implemented — 11 real domain tables + 5 reference tables]
  parsers/        (unchanged this session)                               [implemented — 17 concrete parsers]
  owasp_security/ (unchanged — prior session's leaf package)             [implemented]
  owasp_web/      (unchanged)                                             [implemented]
  linux_advisor/  (unchanged — ADR-0019's separate framework)             [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged — this session's agent/tool reuse this
                   package's engine entirely, never modifying it)        [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +mitre_technique_mapping
                   capability routing (every evidence type), +settings
                   param on _run_specialist_agents,
                   +_hydrate_mitre_mapping_records, +_extract_mitre_mapping)
                   + finding_service.py (unchanged — its
                   generate_findings_for_case is reused as-is) +
                   evidence_service.py, threat_intel_service.py,
                   vulnerability_service.py, linux_security_service.py,
                   linux_advisor_service.py, web_security_service.py,
                   owasp_security_service.py (unchanged); report_service.py [implemented]
data/             (unchanged this session)
scripts/          (unchanged)
tests/
  unit/           202 test modules (+2 this session:
                   test_tools_mitre_tools.py,
                   test_agents_mitre_mapping_agent.py)
  integration:    16 test modules (+0 new files this session; +2 extended:
                   test_case_service_pipeline.py [mitre_technique_count
                   assertion on the SSH-auth-log test],
                   test_investigation_graph.py [node-set assertion
                   extended to the eighth agent])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs + docs/adr/ (23 ADR files incl.
                   template, +0022) + docs/dependency-rules.md (unchanged
                   this session — rule 4/4c already documented
                   core/agents' MITRE import edge in advance) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1546 tests passing as of this session (1533 prior -> 1546 now: 13 new).
Modified this session: `core/graph/{state,investigation_graph}.py`,
`core/services/case_service.py`, `apps/api/{schemas,routers/evidence}.py`,
`docs/roadmap.md`, `core/{agents,tools}/README.md`,
`tests/integration/{test_case_service_pipeline,test_investigation_graph}.py`,
`CHANGELOG.md`, and this file. New: `docs/adr/0022-mitre-mapping-agent.md`,
`core/tools/mitre_tools.py`, `core/agents/mitre_mapping_agent.py`,
`tests/unit/{test_tools_mitre_tools,test_agents_mitre_mapping_agent}.py` —
all currently uncommitted until this session's commit (see "Current Git
Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extended (not reversed) by
ADR-0001 through ADR-0022. **M2 and M4 are both now fully closed.** This
session's deliberate decisions, documented in
`docs/adr/0022-mitre-mapping-agent.md`:

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

**New this session (MITRE Mapping Agent, ADR-0022):**

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

*(M0–M4/ADR-0015–0021 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session (MITRE Mapping Agent, ADR-0022):**

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

1. **M2 — closed this session.** `core/agents/mitre_mapping_agent.py` +
   `core/tools/mitre_tools.py` wrap `core.knowledge.mitre`'s lookup engine
   and `core.findings`'s existing mapping engine (ADR-0022).
2. **M3 — closed** (prior session).
3. **M4 — closed** (prior session). All five specialist-agent pieces
   (Vulnerability Assessment, Threat Hunting, Linux Security Advisor, the
   out-of-blueprint Web Security Agent, and the AST-based OWASP Security
   Agent) are built.
4. **M5 — Incident Response synthesis + Reporting.** Incident Response
   Agent (the correct home for cross-agent recommendation/escalation/
   remediation synthesis — still not built, by design), Report Generator
   Agent, Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports`
   route.
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
   into one shared representation; an asset-criticality inventory.

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
  every file in `core/owasp_security` and `core/owasp_web` (and every
  other file touched this session) passes `mypy --strict` cleanly when
  checked directly (bypassing the numpy-pulling files) — see Key
  Decisions for two latent issues found and fixed in `core/owasp_web`
  along the way. Resolving the numpy/mypy/Python-version mismatch itself
  (pin an older numpy, or bump the mypy `python_version`) remains
  environment maintenance outside any single feature session's scope.
- **`SastAdvice` (this session's output type) is never persisted
  anywhere** — by design (ADR-0021 point 4, matching ADR-0019/0020's
  precedent), not a gap to close later; the same is true of
  `SocFinding`/`PhishingVerdict`/`VulnerabilityFinding`/
  `LinuxSecurityFinding`/`LinuxSecurityAdvice`/`WebSecurityAdvice`, which
  *are* deferred gaps.
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
  optimized this session (ADR-0022) — a future session could add a
  shared-instance seam if profiling ever shows it matters.
- **`MitreCaseMappingSummary` (this session's agent output) is never
  persisted anywhere** — by design, matching `SastAdvice`/
  `WebSecurityAdvice`/`LinuxSecurityAdvice`'s precedent; the underlying
  `Finding.mitre_mappings` data it summarizes *is* already persisted
  (ADR-0013, unchanged).

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`core/tools/mitre_tools.py`/`core/agents/mitre_mapping_agent.py` are pure
Python plus Pydantic, reusing the already-vendored MITRE dataset and the
already-established `core/knowledge/mitre`/`core/findings` engines.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the OWASP Security Agent (AST SAST)
Framework (ADR-0021) commit is committed.

This session's MITRE Mapping Agent work added/modified (all to be
committed in this session's single commit — see the commit hash in this
session's final report):

- New: `docs/adr/0022-mitre-mapping-agent.md`,
  `core/tools/mitre_tools.py`, `core/agents/mitre_mapping_agent.py`,
  `tests/unit/{test_tools_mitre_tools,test_agents_mitre_mapping_agent}.py`.
- Modified: `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`,
  `apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
  `core/{agents,tools}/README.md`,
  `tests/integration/{test_case_service_pipeline,test_investigation_graph}.py`,
  `CHANGELOG.md`, this file.

Full suite (1546 tests), `ruff check`/`format --check`, and
`scripts/check_dependency_rules.py` all pass. `mypy core --strict`
(whole-repo) fails on the same pre-existing, unrelated numpy/environment
issue as prior sessions (see Known Issues); every file this session
touched is individually `mypy --strict` clean.

---

## Next Recommended Prompt

> M2 and M4 are both now fully closed — all eight blueprint-named
> specialist agents built to date exist and are wired into the graph.
> Begin M5 next: the Incident Response Agent (case-wide cross-agent
> synthesis — recommendation/escalation/remediation from every specialist
> agent's already-computed findings, matching NIST SP 800-61) now finally
> has eight specialist agents' worth of findings to meaningfully
> synthesize, or the Report Generator Agent (Jinja2/ReportLab templates,
> Plotly charts, `/api/v1/reports` route) if reporting is the higher
> priority. Confirm with the user which of these two M5 pieces to build
> first before starting — both are named in blueprint §7/§15 as M5 scope,
> and neither has been started. Preserve every existing file and
> architectural decision described in this document — including all eight
> specialist agents (the newest, `MitreMappingAgent`, reuses
> `core/findings`'s existing mapping/confidence/dedup engine entirely; it
> does not duplicate it — see ADR-0022 before assuming a "MITRE" task needs
> a new engine), the Case lifecycle subsystem, the Finding & MITRE Engine,
> the Vulnerability Assessment Framework, the Linux Security Threat Hunting
> Framework, the Linux Security Advisor Framework, the OWASP Web Security
> Agent Framework, and the OWASP Security Agent (AST SAST) Framework — only
> extend them. Also worth addressing eventually (not urgent,
> environment-only): the pre-existing `mypy core --strict` failure caused
> by a numpy/pandas stub incompatibility with the pinned
> `python_version = "3.11"` (see this file's Known Issues) — either pin an
> older `numpy` compatible with the target Python version, or bump the
> `pyproject.toml` mypy `python_version` if the project's actual runtime
> floor has moved past 3.11.
