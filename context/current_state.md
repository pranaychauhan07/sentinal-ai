# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented blueprint §7's **OWASP Security Agent** end-to-end
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
  api/            schemas.py (MODIFIED: +2 SAST response fields) +
                   routers/{system,cases,evidence(MODIFIED: passes through
                   SAST fields),iocs,findings,v1}.py                       [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (MODIFIED: +7 OWASP_SECURITY_* fields +
                   9 evidence extensions)                                 [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py,
                   vulnerability_agent.py, threat_hunter_agent.py,
                   linux_security_agent.py, web_security_agent.py
                   (unchanged) + owasp_security_agent.py (NEW — seventh
                   concrete specialist agent — closes M4)                 [implemented — 7 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py, vuln_tools.py,
                   linux_security_tools.py, linux_tools.py,
                   web_security_tools.py (unchanged) + owasp_tools.py
                   (NEW — OwaspSecurityAssessmentTool, blueprint's exact
                   named file)                                            [implemented — 7 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged)                  [implemented]
  graph/          investigation_graph.py (MODIFIED: +OwaspSecurityAgent
                   wiring) + state.py (MODIFIED: +owasp_security_records
                   field) + routing.py/workflow_engine.py/events.py/
                   retry.py/failure_recovery.py/metrics.py (unchanged)    [implemented]
  db/             models/timeline_event.py (MODIFIED: +SAST_ASSESSED) +
                   migrations/versions/ (+1 NEW: extend
                   timeline_event_type_enum) + all prior migrations
                   (unchanged)                                            [implemented — 11 real domain tables + 5 reference tables]
  parsers/        source_code_parser.py (NEW — SourceCodeParser) +
                   registry.py (MODIFIED: +registration) + all other
                   sixteen parsers (unchanged)                            [implemented — 17 concrete parsers]
  owasp_security/ (NEW leaf package — models, exceptions,
                   language_detector, rule_engine, python_ast_rules,
                   pattern_rules, python_ast_analyzer, pattern_analyzer,
                   vulnerability_detection_engine, secure_coding_advisor,
                   evidence_mapper, confidence_calculator,
                   finding_generator, risk_assessment, text_utils,
                   analysis_engine, metrics, audit)                       [implemented]
  owasp_web/      advisory_engine.py (MODIFIED: fixed a latent mypy-strict
                   variable-reuse issue found this session) +
                   header_rules.py/misconfig_rules.py (MODIFIED: fixed a
                   latent mypy-strict Matcher.kind string-vs-enum issue) +
                   all other modules (unchanged — ADR-0020's framework)   [implemented]
  linux_advisor/  (unchanged — ADR-0019's separate framework)             [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged)                                             [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +owasp_security capability
                   routing, +_run_specialist_agents seventh agent,
                   +_extract_owasp_security) + owasp_security_service.py
                   (NEW — assess_source_code, no DB session) +
                   evidence_service.py, threat_intel_service.py,
                   finding_service.py, vulnerability_service.py,
                   linux_security_service.py, linux_advisor_service.py,
                   web_security_service.py (unchanged); report_service.py [implemented]
data/             sample_evidence/{vulnerable_app.py,safe_app.py,
                   vulnerable_app.js,VulnerableApp.java} (NEW fixtures);
                   all other fixtures (unchanged)
scripts/          (unchanged)
tests/
  unit/           200 test modules (+17 this session:
                   test_owasp_security_{models,rule_engine,
                   language_detector,python_ast_analyzer,
                   pattern_analyzer,vulnerability_detection_engine,
                   secure_coding_advisor,evidence_mapper,
                   confidence_calculator,finding_generator,
                   risk_assessment,analysis_engine,metrics,audit}.py,
                   test_parsers_source_code_parser.py,
                   test_tools_owasp_tools.py,
                   test_agents_owasp_security_agent.py; +1 extended:
                   test_parsers_registry.py [builtin-parser-count
                   assertion])
  integration:    16 test modules (+2 NEW:
                   test_owasp_security_pipeline_integration.py,
                   test_owasp_security_performance.py; +2 extended:
                   test_api_case_routes.py [vulnerable_app.py upload
                   routing test], test_investigation_graph.py [node-set
                   assertion])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs + docs/adr/ (22 ADR files incl.
                   template, +0021) + docs/dependency-rules.md (MODIFIED:
                   rule 4i added, rule 5/layer-stack diagram extended) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1533 tests passing as of this session (1395 prior -> 1533 now: 138 new).
Modified this session: `core/db/models/timeline_event.py`,
`core/config/settings.py`, `.env.example`,
`core/graph/{state,investigation_graph}.py`,
`core/services/case_service.py`, `core/parsers/{models,registry}.py`,
`apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
`docs/dependency-rules.md`, `core/{agents,tools,parsers,services}/README.md`,
`tests/integration/{test_api_case_routes,test_investigation_graph}.py`,
`tests/unit/test_parsers_registry.py`, `CHANGELOG.md`, and this file, plus
three pre-existing files fixed for a latent `mypy --strict` issue
(`core/owasp_web/{advisory_engine,header_rules,misconfig_rules}.py`) — all
currently uncommitted until this session's commit (see "Current Git
Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extended (not reversed) by
ADR-0001 through ADR-0021. **M4 is now fully closed** — every
blueprint-named specialist agent for this milestone exists. Fifteen
deliberate decisions, all documented in
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

`docs/roadmap.md` records M4 as **checked off** (`- [x]`) this session,
with a dated addendum explaining why. No approved architectural decision
(ADR-0001 through 0020) was reversed.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **No conflict to raise this session** — unlike the prior session (which
  had to reconcile a task brief against a different blueprint definition),
  this task matched blueprint §7's OWASP Security Agent exactly. The only
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

*(M0–M4/ADR-0015–0020 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session:**

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

No Incident Response Agent, MITRE Mapping Agent, LLM reasoning,
`/api/v1/reports` route, or `core.security.{pii_redaction,approval_gate}`
implementation exist as public interfaces yet.

---

## Remaining Work

1. **M2 — still open.** A concrete `core/agents/mitre_mapping_agent.py`
   wrapping `core.knowledge.mitre`'s lookup engine.
2. **M3 — closed** (prior session).
3. **M4 — closed this session.** All five specialist-agent pieces
   (Vulnerability Assessment, Threat Hunting, Linux Security Advisor, the
   out-of-blueprint Web Security Agent, and now the AST-based OWASP
   Security Agent) are built.
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

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`core/owasp_security` is pure Python (stdlib `ast`/`re`) plus Pydantic,
reusing the already-vendored parser layer. JavaScript/TypeScript/Java
support is deliberately pattern-based rather than adding a new AST
dependency this session (ADR-0021).

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the OWASP Web Security Agent Framework
(ADR-0020) commit is committed.

This session's OWASP Security Agent Framework work added/modified (all to
be committed in this session's single commit — see the commit hash in this
session's final report):

- New: `docs/adr/0021-owasp-security-agent-ast-sast.md`, the full
  `core/owasp_security/` package (19 files incl. `__init__.py`/`README.md`),
  `core/parsers/source_code_parser.py`,
  `core/services/owasp_security_service.py`,
  `core/tools/owasp_tools.py`, `core/agents/owasp_security_agent.py`, one
  new Alembic migration, four `data/sample_evidence/` fixtures, 17 new
  unit test files + 2 new integration test files.
- Modified: `core/db/models/timeline_event.py`, `core/config/settings.py`,
  `.env.example`, `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`, `core/parsers/{models,registry}.py`,
  `apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
  `docs/dependency-rules.md`,
  `core/{agents,tools,parsers,services}/README.md`,
  `tests/integration/{test_api_case_routes,test_investigation_graph}.py`,
  `tests/unit/test_parsers_registry.py`, `CHANGELOG.md`, this file, and
  (latent mypy-strict fixes, unrelated to this session's feature but
  discovered while verifying it) `core/owasp_web/{advisory_engine,
  header_rules,misconfig_rules}.py`.

Full suite (1533 tests), `ruff check`/`format --check`, and
`scripts/check_dependency_rules.py` all pass. `mypy core --strict`
(whole-repo) fails on a pre-existing, unrelated numpy/environment issue
(see Known Issues); every file this session touched is individually
`mypy --strict` clean.

---

## Next Recommended Prompt

> M4 is now fully closed. Close out M2 next with a concrete
> `core/agents/mitre_mapping_agent.py` wrapping `core.knowledge.mitre`'s
> existing `MitreLookup` (returning "unmapped" rather than a low-confidence
> guess when nothing matches), which is the one piece keeping M2's
> `docs/roadmap.md` checkbox open. Follow the exact three-step extension
> pattern all seven specialist agents now demonstrate: a
> parser/tool in its owning leaf package (or none, if this agent only
> reasons over already-hydrated case state — MITRE mapping is
> cross-cutting, consumed by SOC/Threat Hunting/Incident agents per
> blueprint §7, so check whether it needs its own `EvidenceType` at all
> before assuming it does), an agent in `core/agents/` declaring a
> distinct capability, and two lines in
> `core/graph/investigation_graph.py`. Alternatively, begin M5: the
> Incident Response Agent (case-wide cross-agent synthesis — recommendation/
> escalation/remediation from every specialist agent's already-computed
> findings, matching NIST SP 800-61) now finally has enough specialist
> agents' findings to meaningfully synthesize (seven agents' worth), or the
> Report Generator Agent (Jinja2/ReportLab templates, Plotly charts,
> `/api/v1/reports` route) if reporting is the higher priority. Do **not**
> build Incident Response before confirming with the user which of M2/M5
> is the intended next milestone — a prior session explicitly deferred
> Incident Response as "belongs to M5, needs more specialist findings
> first," and that condition is now satisfied, but M2's MITRE Mapping Agent
> is the smaller, longer-standing gap. Preserve every existing file and
> architectural decision described in this document — including all seven
> specialist agents, the Case lifecycle subsystem, the Finding & MITRE
> Engine, the Vulnerability Assessment Framework, the Linux Security Threat
> Hunting Framework, the Linux Security Advisor Framework, the OWASP Web
> Security Agent Framework, and the OWASP Security Agent (AST SAST)
> Framework — only extend them. Also worth addressing eventually (not
> urgent, environment-only): the pre-existing `mypy core --strict` failure
> caused by a numpy/pandas stub incompatibility with the pinned
> `python_version = "3.11"` (see this file's Known Issues) — either pin an
> older `numpy` compatible with the target Python version, or bump the
> `pyproject.toml` mypy `python_version` if the project's actual runtime
> floor has moved past 3.11.
