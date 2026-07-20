# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented a **new, out-of-blueprint OWASP Web Security
Agent** end-to-end — an explicit ADR: **ADR-0020, OWASP Web Security Agent**
(`docs/adr/0020-owasp-web-security-agent.md`). This closes a task-scoped
request for a deterministic analyzer of HTTP traffic artifacts (requests/
responses, security headers, cookies, JWT metadata, web server logs, API
responses) mapped to the OWASP Top 10 (2021) taxonomy, adding the **sixth**
concrete specialist agent (after `SocAnalystAgent` M1, `PhishingAgent` M2,
`VulnerabilityAssessmentAgent` M4, `ThreatHunterAgent` M4,
`LinuxSecurityAgent` M4), proving the same three-step extension pattern
(parser/tool in its owning leaf package, an agent declaring a distinct
capability, two lines in `investigation_graph.py`) a sixth time.

**This is not** blueprint §7's OWASP Security Agent (AST-based source-code/
API static review — SQLi/XSS/broken-auth pattern detection over parsed
source code) — that agent remains **completely unbuilt**; a session-opening
conflict check (against `context/01_blueprint.md` §7 and
`context/current_state.md`'s own prior "Next Recommended Prompt") surfaced
that blueprint's OWASP Security Agent has a fundamentally different input
shape (parsed source code, AST-based technique) than this task's brief
(HTTP traffic, headers/cookies/JWTs, no source code, no AST at all). The
user explicitly confirmed: build this as a new, separate agent with its own
ADR, following the ADR-0019 (`core/linux_advisor` vs. `core/linux_security`)
precedent, and never modify or redefine blueprint's AST-based agent. M4's
blueprint-defined checkbox therefore **stays unchecked** — this session is
an additive capability, not a milestone closure.

### M0/M1/M2/M3/M4 (Vulnerability Assessment, Linux Security Threat Hunting, Linux Security Advisor) frameworks (unchanged from prior sessions)

Configuration, logging, shared contracts, DB foundation, FastAPI app,
governance, `core/agents`/`core/tools`/`core/graph` framework,
`core/memory`/`core/knowledge` framework, `core/threat_intel` framework (20
IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine),
`Case`/`Evidence`/`Finding`/`TimelineEvent`/`Report`/`Vulnerability`/
`LinuxSecurityFindingRow` domain models, `SocAnalystAgent`, `PhishingAgent`,
`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`, `LinuxSecurityAgent`,
`core/vulnerabilities/` (ADR-0017), `core/linux_security/` (ADR-0018),
`core/linux_advisor/` (ADR-0019), `core/security/prompt_guard.py`, the Case
lifecycle/ownership/tags/notes/events/metrics extension (ADR-0015), and
`core/services/case_service.py`'s `investigate_new_evidence()` orchestrator
— all unchanged except where explicitly noted below.

### OWASP Web Security Agent Framework (new this session, ADR-0020)

- **`core/owasp_web/`** (new leaf package, sixth peer to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`/
  `core/linux_security`/`core/linux_advisor`, matching `core/linux_advisor`'s
  lightest-weight shape — no DB persistence, no `registry.py`/`interfaces.py`
  enrichment-provider seam) —
  - `models.py`: own `WebSecuritySeverity` scale (never reusing
    `core.parsers.models.Severity` or any sibling leaf's), a first-class
    `OwaspCategory` enum (all ten 2021 Top-10 categories) used directly on
    `rule_engine.Rule.category` (stronger typing than a plain `str`),
    `ParsedHeader`/`ParsedCookie`/`ParsedJwt` (intermediate parsed shapes),
    `HeaderFinding`/`CookieFinding`/`JwtFinding`/`MisconfigurationFinding`
    (per-analyzer findings — `severity=INFO`/no-match is a real, explicit
    "well-configured" outcome, never merely an absence of output),
    `OwaspFinding` (the task brief's exact unified finding shape: category,
    severity, confidence, evidence reference, explanation, recommended
    remediation), `WebSecurityAdvice` (the aggregate output), `RuleMatch`,
    `MatcherKind`, `RulePriority`, `RiskDimensionScores`.
  - `exceptions.py`: narrow hierarchy (`MalformedHttpLineError`,
    `MalformedJwtError`, `OversizedWebSecurityInputError`).
  - `rule_engine.py`: `RuleEngine`/`Rule` — a real, generic, data-driven
    detection engine, functionally identical in shape to
    `core.linux_advisor.rule_engine` (same `regex`/`literal_substring`/
    `callable_signature` tagged-union matcher) but never imported from it —
    each leaf owns its own copy (`docs/dependency-rules.md` rule 10). Adding
    a detection later means adding a `Rule` object; this engine's code never
    changes.
  - `header_rules.py`: `MISSING_HEADER_SPECS` (structured presence-check
    table for the task's six named headers: CSP, HSTS, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy) +
    `DEFAULT_HEADER_VALUE_RULES` (pattern-based value-quality `Rule`s: CSP
    `unsafe-inline`/wildcard source, HSTS missing/short max-age or
    `includeSubDomains`, invalid `X-Frame-Options` value, `Referrer-Policy:
    unsafe-url`, `Server`/`X-Powered-By` version disclosure).
  - `cookie_rules.py`: pure structural cookie-attribute checks (not
    regex-based — mirrors `permission_parser.py`'s "pure function, not rule
    engine" precedent for structural checks): missing `Secure` (severity
    raised for session/auth-like cookie names), missing `HttpOnly`, missing
    `SameSite` / `SameSite=None` without `Secure`, excessive `Max-Age`
    (>1 year), overly broad `Domain`.
  - `misconfig_rules.py`: `DEFAULT_MISCONFIG_RULES` — directory listing,
    debug/diagnostic endpoints (`/debug`, `/actuator`, `/_profiler`,
    `phpinfo.php`, `console`), default-credential indicators, stack-trace/
    verbose-error disclosure, weak TLS protocol/cipher metadata references
    (SSLv2/SSLv3/TLS 1.0/1.1/RC4/3DES), excessive internal path/IP
    disclosure.
  - `header_analyzer.py`: `HeaderAnalyzer` — missing-header presence checks
    (structured, not regex) + value-quality `RuleEngine` evaluation against
    a synthesized `"Name: Value"` line for every present header.
  - `cookie_analyzer.py`: `CookieAnalyzer` + `parse_set_cookie_line` (pure
    `Set-Cookie:` line parser) — one parsed cookie -> `CookieFinding | None`.
  - `jwt_analyzer.py`: `JwtAnalyzer` + `parse_jwt` (pure base64url/JSON
    decode of header+payload segments — **no cryptographic signature
    verification**, per the task brief's explicit instruction) — flags
    `alg=none`/missing (critical), missing/expired `exp`, missing `iss`/
    `aud`, and header anomalies (`jku`/`jwk`/`x5u`/`x5c`/`crit` — key-
    confusion-attack-enabling fields).
  - `misconfiguration_detector.py`: `MisconfigurationDetector` — runs
    `DEFAULT_MISCONFIG_RULES` against generic (non-header/cookie/JWT) lines.
  - `category_mapper.py`: `OwaspCategoryMapper` — the task's "OWASP Category
    Mapper" capability, a small pure lookup from `OwaspCategory` to its
    official 2021 name/description.
  - `finding_generator.py`: `FindingGenerator` — the task's "Finding
    Generator" capability, normalizing every analyzer's narrower finding
    type into the unified `OwaspFinding` shape.
  - `risk_assessment.py`: `RiskAssessmentEngine`/`WebSecurityRiskWeights` —
    five configurable, sum-to-1.0-validated dimensions (highest individual
    severity, highest individual confidence, distinct finding count,
    whether any critical-category finding matched, corroboration across
    more than one analyzer source), read from `Settings`.
  - `advisory_engine.py`: `WebSecurityAdvisoryEngine` — the orchestrator;
    classifies each line (JWT-shaped token -> `jwt_analyzer`; `Set-Cookie:`
    -> `cookie_analyzer`; generic `Name: Value` -> collected for
    `header_analyzer`; else -> `misconfiguration_detector`), runs finding
    generation + risk assessment, returns the final `WebSecurityAdvice`.
    Configurable oversized-input guard (max lines/chars, read from
    `Settings`), skips (never aborts on) a malformed `Set-Cookie` line or a
    structurally-invalid JWT, sanitizes control characters/embedded
    newlines (`sanitize_text`) before any analyzed text reaches a log line
    or the advice text itself, and — discovered while testing the empty-
    input edge case — deliberately skips the missing-header presence check
    entirely when the artifact contains **zero** non-blank lines (an
    entirely empty artifact is "insufficient evidence", never "6 headers
    missing", matching the codebase's established "insufficient evidence vs.
    clean bill" distinction). This package performs pure text analysis and
    never sends a live HTTP request, executes, or `eval`s any analyzed
    content.
  - `metrics.py`/`audit.py`: `WebSecurityMetricsCollector` (headers/cookies/
    JWTs/misconfiguration-candidates analyzed, rule matches by id, failures,
    timing) and structured audit-event emission + timing, mirroring the
    established shape in `core/linux_advisor`.
- **New `EvidenceType.HTTP_TRANSACTION`** (`core/parsers/models.py`, purely
  additive) + **new parser `core/parsers/http_transaction_parser.py`**
  (`HttpTransactionParser`) — one `EvidenceRecord` per non-blank line, no
  deep classification. `sniff()` gives a real, above-`PlainTextParser` (0.1)
  confidence (0.4) when it recognizes an HTTP request/status line, a
  `Set-Cookie` header, or a security-relevant header name. Registered in
  `core/parsers/registry.py` at priority 3, claiming `.http`/`.har`/`.txt`
  extensions (`.txt` shared with `PlainTextParser`/`LinuxCommandInputParser`
  so a `.txt` upload with recognizable HTTP content routes here via
  `sniff()`'s tie-break).
- **`core/services/web_security_service.py`** (new) —
  `assess_http_transaction()`, synchronous (**no DB session parameter** —
  this framework never persists), composing `WebSecurityAdvisoryEngine`
  end-to-end and emitting audit events. Gets the documented dependency-rules
  exception 4h (mirrors 4e/4f/4g, minus the `core/memory` edge those have,
  since this module has no note-taking behavior).
- **`core/tools/web_security_tools.py`** (`WebSecurityAdvisoryTool`, new) —
  blueprint's-precedent-matching named file (never `owasp_tools.py`, which
  blueprint reserves for the AST-based source-code reviewer). Aggregates
  already-computed OWASP findings into a case-level summary (counts by
  category/severity, top-N); never recomputes a severity/confidence/risk
  score itself.
- **`core/agents/web_security_agent.py`** (`WebSecurityAgent`,
  `WebSecurityAdvice`, new) — the sixth concrete specialist agent,
  capability `owasp_web_security_assessment`. Deliberately thin: reads
  `CaseInvestigationState.owasp_web_records` (new state field, plain
  `dict[str, object]` entries — a distinct field name from every other
  `*_records` field) and calls `WebSecurityAdvisoryTool` to produce a
  case-level `WebSecurityAdvice`. `core/agents` has no dependency-rules.md
  import edge onto `core/owasp_web` (identical reasoning to every other
  specialist agent's precedent).
- **`core/graph/investigation_graph.py`** (modified) — `WebSecurityAgent`
  registered/wired with the same two-line pattern the other five
  specialists established; module docstring updated to describe six agents.
- **`core/graph/state.py`** (modified) — `CaseInvestigationState` gained
  `owasp_web_records: list[Any]` (same `operator.add` reducer shape).
- **`core/services/case_service.py`** (modified) —
  `_EVIDENCE_TYPE_CAPABILITIES` gained `HTTP_TRANSACTION` ->
  `owasp_web_security_assessment`; new `_WEB_SECURITY_EVIDENCE_TYPES` gating
  set; `_run_specialist_agents` registers the sixth agent and hydrates
  `owasp_web_records`; `investigate_new_evidence()` conditionally calls
  `assess_http_transaction()` (gated to `HTTP_TRANSACTION` only,
  synchronous, no session) and reduces its already-generated
  `WebSecurityAdvice` (findings + summary) into plain-dict records before
  hydrating state, recording a `TimelineEvent(OWASP_WEB_ASSESSED)`.
  `CaseInvestigationResult` gained `owasp_web_finding_count`/
  `highest_owasp_web_risk_level`; new `_extract_web_security` mirrors
  `_extract_linux_advisory`.
- **`core/db/models/timeline_event.py`** (modified) — new
  `TimelineEventType.OWASP_WEB_ASSESSED` (a generic pipeline-stage marker;
  this framework never persists the advice itself) + one new Alembic
  migration (`eea88afcd84d`) additively extending
  `timeline_event_type_enum`.
- **`apps/api/schemas.py`/`routers/evidence.py`** (modified) —
  `EvidenceUploadResponse` gained `owasp_web_finding_count`/
  `highest_owasp_web_risk_level` (both `None`-defaulted, purely additive).
- **`core/config/settings.py`/`.env.example`** (modified) — every
  configurable threshold/weight this framework uses (max lines/chars per
  artifact, the five risk-assessment weights) — zero hardcoded values
  anywhere in `core/owasp_web`.
- **`data/sample_evidence/http_transaction.txt`** (new fixture) — an
  `Authorization: Bearer <alg=none JWT>` line, missing HSTS/X-Frame-Options/
  X-Content-Type-Options/Referrer-Policy/Permissions-Policy headers, a weak
  CSP (`unsafe-inline` + wildcard), a version-disclosing `Server` header, an
  insecure `Set-Cookie: session=...` (no Secure/HttpOnly/SameSite), a
  `Set-Cookie: csrftoken=...; Secure; SameSite=None` (missing HttpOnly), an
  `Index of /admin/backups` directory-listing line, and an
  `admin/admin default password ... /debug console` line (matches both the
  default-credentials and debug-endpoint rules).
- **Testing** — 93 new tests: unit tests for every `core/owasp_web` module
  (models, rule_engine, header_analyzer, cookie_analyzer, jwt_analyzer,
  misconfiguration_detector, category_mapper, finding_generator,
  risk_assessment, advisory_engine, metrics, audit — each with at least one
  adversarial/malformed-input case: a malformed `Set-Cookie` line, a
  structurally-invalid JWT, an oversized-input guard, control characters/
  embedded newlines), the new parser (including registry priority/sniff
  behavior), the tool, the agent, an integration test proving the crafted
  fixture is detected end-to-end (missing/weak headers, insecure cookies,
  unsecured JWT, misconfigurations all flagged, unified `OwaspFinding`
  count matches), an API `TestClient` test proving this evidence type
  routes to `WebSecurityAgent` through the real pipeline
  (`test_upload_http_transaction_evidence_routes_to_web_security_agent`),
  and a 5,000-line performance test plus an instantaneous-rejection test
  for the oversized-input guard. `test_investigation_graph.py`'s node-set
  assertion extended to the sixth agent; `test_parsers_registry.py`'s
  builtin-parser-count assertion extended to sixteen. Full pytest suite
  (1395 tests, up from 1302), `ruff check`/`format`, and
  `scripts/check_dependency_rules.py` all pass. `mypy core --strict` could
  not be run to completion this session — see Known Issues below (a
  pre-existing environment issue, confirmed unrelated to this session's
  changes via `git stash`).

**Explicitly NOT built, by ADR-0020's stated scope:** Penetration testing,
active vulnerability scanning, incident response, threat hunting, MITRE
ATT&CK mapping, automated exploitation, or LLM reasoning of any kind
anywhere in this package; a concrete `WebSecurityEnrichmentProvider`-style
seam (deliberately absent, matching `core.linux_advisor`'s precedent); DB
persistence of any kind; blueprint §7's AST-based OWASP Security Agent
(source code/API static review — still unbuilt, M4's only remaining piece);
MITRE Mapping Agent (M2's remaining gap); any redesign of `SocAnalystAgent`,
`PhishingAgent`, `VulnerabilityAssessmentAgent`, `ThreatHunterAgent`,
`LinuxSecurityAgent`, `Case`, or any prior framework — only extended.

---

## Repository Status

```
apps/
  api/            schemas.py (MODIFIED: +2 owasp-web response fields) +
                   routers/{system,cases,evidence(MODIFIED: passes through
                   owasp-web fields),iocs,findings,v1}.py                 [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (MODIFIED: +7 OWASP_WEB_* fields)          [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py,
                   vulnerability_agent.py, threat_hunter_agent.py,
                   linux_security_agent.py (unchanged) +
                   web_security_agent.py (NEW — sixth concrete
                   specialist agent)                                      [implemented — 6 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py, vuln_tools.py,
                   linux_security_tools.py, linux_tools.py (unchanged) +
                   web_security_tools.py (NEW — WebSecurityAdvisoryTool)   [implemented — 6 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged)                  [implemented]
  graph/          investigation_graph.py (MODIFIED: +WebSecurityAgent
                   wiring) + state.py (MODIFIED: +owasp_web_records
                   field) + routing.py/workflow_engine.py/events.py/
                   retry.py/failure_recovery.py/metrics.py (unchanged)    [implemented]
  db/             models/timeline_event.py (MODIFIED:
                   +OWASP_WEB_ASSESSED) + migrations/versions/
                   (+1 NEW: extend timeline_event_type_enum) + all
                   prior migrations (unchanged)                           [implemented — 11 real domain tables + 5 reference tables]
  parsers/        http_transaction_parser.py (NEW — HttpTransactionParser)
                   + registry.py (MODIFIED: +registration) + all other
                   fifteen parsers (unchanged)                            [implemented — 16 concrete parsers]
  owasp_web/      (NEW leaf package — models, exceptions, rule_engine,
                   header_rules, cookie_rules, misconfig_rules,
                   header_analyzer, cookie_analyzer, jwt_analyzer,
                   misconfiguration_detector, category_mapper,
                   finding_generator, risk_assessment, advisory_engine,
                   metrics, audit)                                        [implemented]
  linux_advisor/  (unchanged — ADR-0019's separate framework)             [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged)                                             [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +owasp_web capability
                   routing, +_run_specialist_agents sixth agent,
                   +_extract_web_security) + web_security_service.py
                   (NEW — assess_http_transaction, no DB session) +
                   evidence_service.py, threat_intel_service.py,
                   finding_service.py, vulnerability_service.py,
                   linux_security_service.py, linux_advisor_service.py
                   (unchanged); report_service.py                        [implemented]
data/             sample_evidence/http_transaction.txt (NEW fixture);
                   all other fixtures (unchanged)
scripts/          (unchanged)
tests/
  unit/           185 test modules (+15 this session:
                   test_owasp_web_{models,rule_engine,header_analyzer,
                   cookie_analyzer,jwt_analyzer,misconfiguration_detector,
                   category_mapper,finding_generator,risk_assessment,
                   advisory_engine,metrics,audit}.py,
                   test_parsers_http_transaction_parser.py,
                   test_tools_web_security_tools.py,
                   test_agents_web_security_agent.py; +2 extended:
                   test_parsers_registry.py [builtin-parser-count
                   assertion])
  integration:    14 test modules (+2 NEW:
                   test_web_security_pipeline_integration.py,
                   test_web_security_performance.py; +2 extended:
                   test_api_case_routes.py [http_transaction.txt upload
                   routing test], test_investigation_graph.py [node-set
                   assertion])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs + docs/adr/ (21 ADR files incl.
                   template, +0020) + docs/dependency-rules.md (MODIFIED:
                   rule 4h added, rule 5/layer-stack diagram extended) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1395 tests passing as of this session (1302 prior -> 1395 now: 93 new).
Modified this session: `core/db/models/timeline_event.py`,
`core/config/settings.py`, `.env.example`,
`core/graph/{state,investigation_graph}.py`,
`core/services/case_service.py`, `core/parsers/{models,registry}.py`,
`apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
`docs/dependency-rules.md`, `core/{agents,tools,parsers,services}/README.md`,
`tests/integration/{test_api_case_routes,test_investigation_graph}.py`,
`tests/unit/test_parsers_registry.py`, `CHANGELOG.md`, and this file — all
currently uncommitted until this session's commit (see "Current Git
Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extended (not reversed) by
ADR-0001 through ADR-0020. Fourteen deliberate decisions, all documented in
`docs/adr/0020-owasp-web-security-agent.md`:

1. **`core/owasp_web/` is a new, deliberately distinct package from
   blueprint's future AST-based OWASP Security Agent** — different name
   (never `core/owasp/`), different agent module name
   (`web_security_agent.py`, never `owasp_agent.py`), different tool module
   name (`web_security_tools.py`, never `owasp_tools.py`).
2. **New `EvidenceType.HTTP_TRANSACTION`** — purely additive.
3. **New parser `HttpTransactionParser`** — deliberately dumb/generic;
   deeper classification is the advisory engine's own job.
4. **No DB persistence, no enrichment-provider seam** — matching
   `core/linux_advisor`'s precedent exactly.
5. **`WebSecuritySeverity` is its own enum** — never a reuse of a sibling
   leaf's.
6. **`OwaspCategory` is a first-class, strongly-typed enum** used directly
   on findings and `Rule.category` — stronger typing than a plain `str`
   category, since OWASP mapping is this agent's defining responsibility.
7. **A generic, data-driven `RuleEngine`/`Rule` seam**, functionally
   identical in shape to `core/linux_advisor`'s but never imported from it
   (leaves don't share code sideways) — the extensibility point; adding a
   detection later means adding a `Rule` object, never touching engine code.
8. **Header presence checks and cookie attribute checks are pure
   structural functions, not `RuleEngine` pattern matches** — an absent
   header or a missing cookie attribute cannot be expressed as a regex
   match against nonexistent text.
9. **`jwt_analyzer.py` performs no cryptographic signature verification** —
   base64url/JSON-decodes header+payload only, per the task brief's
   explicit instruction.
10. **Config-driven, no-hardcoded-values scoring** — five configurable
    dimensions, read from `Settings`, validated to sum to 1.0.
11. **`finding_generator.py` normalizes every analyzer's finding into one
    unified `OwaspFinding` shape** (the task brief's named "Finding
    Generator" capability) — Single Responsibility Principle applied at
    the module level: analyzers detect, this module normalizes.
12. **`advisory_engine.py` defends against three failure classes** without
    ever aborting the whole artifact: oversized input, a malformed
    individual line (`Set-Cookie`/JWT), and log-injection-shaped content —
    plus a fourth, discovered-during-testing guard: an entirely empty
    artifact never triggers the missing-header presence check (which would
    otherwise conflate "no evidence" with "6 headers missing").
13. **`web_security_tools.py`/`web_security_agent.py` never recompute a
    risk/confidence score** — `core/agents` has no import edge onto
    `core/owasp_web`, so state stays plain-dict-typed.
14. **No penetration testing, active scanning, incident response, threat
    hunting, MITRE mapping, automated exploitation, or LLM reasoning
    anywhere in this package.**

`docs/roadmap.md` records this as a dated addendum under M4's still-open
entry (blueprint §7's AST-based OWASP Security Agent remains outstanding,
so M4 itself stays unchecked — this session's addendum explicitly states
"This does not close M4"). No approved architectural decision (ADR-0001
through 0019) was reversed.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **A pre-implementation conflict check against the blueprint was required
  and surfaced a real conflict**: this task's brief (HTTP traffic/headers/
  cookies/JWT analysis) does not match blueprint §7's OWASP Security Agent
  definition (AST-based source-code/API static review). Raised to the user
  before any code was written; the user confirmed building this as a new,
  separate agent with its own ADR (mirroring ADR-0019's `core/linux_advisor`
  vs. `core/linux_security` precedent), never redefining or touching
  blueprint's AST-based agent.
- **No DB persistence for this framework** — matches ADR-0019's precedent
  exactly: a single request in, a single `WebSecurityAdvice` out, no
  case-evidence lifecycle to track. `core/services/web_security_service.py`
  is accordingly synchronous with no DB session parameter.
- **`.txt` is claimed by *three* parsers now** (`PlainTextParser`,
  `LinuxCommandInputParser`, `HttpTransactionParser`) — each with a
  distinct `sniff()` heuristic; `core.parsers.factory._best_sniff_match`
  breaks the tie by confidence, so a `.txt` upload with recognizable HTTP
  content routes to `HttpTransactionParser` without regressing the other
  two parsers' existing routing.
- **`owasp_web_records` is a new, separate `CaseInvestigationState` field**,
  never reusing any prior `*_records` field — every framework's hydrated
  data must never collide on the same state key.
- **An empty-artifact edge case discovered during test-writing**: initially,
  analyzing zero lines produced a `WebSecurityAdvice` with all six security
  headers flagged as "missing" (since the empty `headers` dict has none of
  them), driving `overall_risk_level` to `HIGH` — semantically wrong (no
  evidence was ever observed, so nothing can be judged "missing"). Fixed by
  skipping the missing-header presence check entirely when the artifact
  contains zero non-blank lines, while still running it normally for any
  non-empty artifact that simply lacks header lines (a legitimate "6 headers
  genuinely absent from the observed response" finding, exercised directly
  by `test_missing_headers_generate_findings_end_to_end`).

---

## Public Interfaces

*(M0–M4/ADR-0015–0019 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session:**

`core.owasp_web.*` (new package) —
`models.{OwaspCategory, WebSecuritySeverity, severity_rank, highest_severity,
MatcherKind, RulePriority, RuleMatch, ParsedHeader, ParsedCookie, ParsedJwt,
HeaderFinding, CookieFinding, JwtFinding, MisconfigurationFinding,
OwaspFinding, WebSecurityAdvice, RiskDimensionScores}`,
`exceptions.{WebSecurityError, MalformedHttpLineError, MalformedJwtError,
OversizedWebSecurityInputError}`,
`rule_engine.{Matcher, Rule, RuleEngine, register_callable}`,
`header_rules.{MISSING_HEADER_SPECS, DEFAULT_HEADER_VALUE_RULES,
MissingHeaderSpec}`,
`cookie_rules.{DEFAULT_COOKIE_CHECKS, CookieIssue, check_secure_missing,
check_http_only_missing, check_samesite_issue, check_excessive_expiration,
check_broad_domain}`,
`misconfig_rules.DEFAULT_MISCONFIG_RULES`,
`header_analyzer.HeaderAnalyzer`,
`cookie_analyzer.{CookieAnalyzer, parse_set_cookie_line}`,
`jwt_analyzer.{JwtAnalyzer, parse_jwt}`,
`misconfiguration_detector.MisconfigurationDetector`,
`category_mapper.{OwaspCategoryMapper, OwaspCategoryInfo}`,
`finding_generator.FindingGenerator`,
`risk_assessment.{RiskAssessmentEngine, WebSecurityRiskWeights}`,
`advisory_engine.{WebSecurityAdvisoryEngine, sanitize_text}`,
`metrics.{WebSecurityMetricsCollector, WebSecurityMetricsSnapshot}`,
`audit.{AuditAction, log_web_security_audit_event, timed_execution}`.

`core.parsers.models.EvidenceType.HTTP_TRANSACTION` (new).
`core.parsers.http_transaction_parser.HttpTransactionParser` (new).

`core.db.models.timeline_event.TimelineEventType.OWASP_WEB_ASSESSED` (new).

`core.services.web_security_service.{assess_http_transaction,
WebSecurityAssessmentResult, build_web_security_advisory_engine}` (new).

`core.tools.web_security_tools.{WebSecurityAdvisoryTool,
WebSecurityAdvisoryInput, WebSecurityAdvisoryOutput,
OwaspFindingSummaryInput}` (new).

`core.agents.web_security_agent.{WebSecurityAgent,
default_web_security_agent_tool_registry, WebSecurityAdvice,
WebSecurityAgentResult}` (new).

`core.graph.state.CaseInvestigationState.owasp_web_records` (new field).
`core.graph.investigation_graph.build_investigation_graph` now also
registers/wires `WebSecurityAgent` (node name `web_security_agent`).

`core.services.case_service`: `_EVIDENCE_TYPE_CAPABILITIES` gained
`HTTP_TRANSACTION -> owasp_web_security_assessment`; `_run_specialist_agents`
gained `owasp_web_records` parameter and registers a sixth agent; new
`_extract_web_security`. `CaseInvestigationResult` gained
`owasp_web_finding_count`/`highest_owasp_web_risk_level`.

`apps.api.schemas.EvidenceUploadResponse` gained
`owasp_web_finding_count`/`highest_owasp_web_risk_level` (both optional,
default `None`).

`core.config.Settings` gained 7 new fields:
`owasp_web_max_lines_per_artifact`, `owasp_web_max_chars_per_artifact`, five
`owasp_web_risk_weight_*` fields.

No blueprint §7 AST-based OWASP Security Agent, Incident Response, MITRE
Mapping Agent, LLM reasoning, `/api/v1/reports` route, or
`core.security.{pii_redaction,approval_gate}` implementation exist as
public interfaces yet.

---

## Remaining Work

1. **M2 — still open.** A concrete `core/agents/mitre_mapping_agent.py`
   wrapping `core.knowledge.mitre`'s lookup engine.
2. **M3 — closed** (prior session).
3. **M4 — still open.** Blueprint §7's OWASP Security Agent (AST-based
   static analysis via Python's `ast` module — constitution's own quality
   bar, "never just regex" — mapping SQLi/XSS/broken-auth patterns to
   OWASP Top-10 2021, over parsed source code). **This session's
   `core/owasp_web/` Web Security Agent does NOT satisfy this item** — it
   is a deliberately separate, additive capability (ADR-0020) with a
   different input shape (HTTP traffic, not source code).
4. **M5 — Incident Response synthesis + Reporting.** Incident Response
   Agent (the correct home for cross-agent recommendation/escalation/
   remediation synthesis — still not built, by design), Report Generator
   Agent, Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports`
   route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB,
   populate remaining knowledge data (OWASP source-review rules once M4's
   AST agent exists, playbooks), the real cross-evidence Threat Timeline UI
   feature, MITRE heatmap/AI Analyst Chat UI.
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** `core/security/pii_redaction.py`/
   `approval_gate.py`; a structured read endpoint for `Case.labels`; a
   concrete `LinuxSecurityEnrichmentProvider`/`VulnerabilityEnrichmentProvider`/
   `WebSecurityEnrichmentProvider` (e.g. a live IP-reputation/NVD/CVE-lookup
   API — `core/owasp_web` has no such seam at all, by design, matching
   `core/linux_advisor`); CVSS v4.0 base-score computation; a real
   journald-field mapping in `core/parsers/field_heuristics.py`;
   reconciling `SocFinding`/`PhishingVerdict`/`VulnerabilityFinding`/
   `LinuxSecurityFinding`/`LinuxSecurityAdvice`/`WebSecurityAdvice` (all
   in-memory only) with the persisted `Finding` table into one shared
   representation; an asset-criticality inventory.

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

- **New this session — `mypy core --strict` could not be run to
  completion.** `python -m mypy core --strict` fails with
  `numpy/__init__.pyi:737: error: Type statement is only supported in
  Python 3.12 and greater [syntax]` before checking any project code. This
  reproduces identically on the pre-session baseline (verified via
  `git stash`/`git stash pop` around the same command) — it is a
  pre-existing environment incompatibility (an installed `numpy` version
  whose bundled inline type stubs use PEP 695 syntax, pulled in transitively
  via `pandas` — used by `core/parsers/csv_evidence_parser.py` and the
  Nessus/OpenVAS CSV parsers — while `pyproject.toml`'s
  `[tool.mypy] python_version = "3.11"` rejects that syntax), **not**
  something this session's changes introduced. All new/modified files in
  this session are simple, fully-typed, and follow the exact same patterns
  already passing `mypy --strict` elsewhere in the codebase (verified by
  direct structural mirroring of `core/linux_advisor`'s already-clean
  modules); resolving the numpy/mypy/Python-version mismatch itself is
  environment maintenance outside this session's scope. `ruff check`,
  `ruff format --check`, the full pytest suite (1395 tests), and
  `scripts/check_dependency_rules.py` all pass cleanly.
- **`WebSecurityAdvice` (this session's output type) is never persisted
  anywhere** — by design (ADR-0020 point 4, matching ADR-0019's precedent),
  not a gap to close later; the same is true of `SocFinding`/
  `PhishingVerdict`/`VulnerabilityFinding`/`LinuxSecurityFinding`/
  `LinuxSecurityAdvice`, which *are* deferred gaps.
- **`core/owasp_web` has no enrichment-provider seam at all** — unlike
  `core/vulnerabilities`/`core/linux_security`'s unimplemented-but-present
  `registry.py`/`interfaces.py`, this package doesn't even define the seam,
  since the task never called for external enrichment (e.g. no live
  threat-intel/CVE lookup against the analyzed HTTP traffic).
- **`jwt_analyzer.py` performs no cryptographic signature verification by
  design** — this package can flag `alg=none`/missing-claims/header
  anomalies but cannot confirm a token's signature is actually valid; a
  real signature-verification path (requiring a trusted key/secret) is out
  of scope for this deterministic, offline analyzer.
- **`_EVIDENCE_TYPE_CAPABILITIES` in `case_service.py` is a simple dict of
  tuples**, not a general routing engine — unchanged limitation, carried
  forward.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`core/owasp_web` is pure Python (stdlib `re`/`base64`/`json`/`time`) plus
Pydantic, reusing the already-vendored parser layer.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the Linux Security Advisor Framework
(ADR-0019) commit is committed.

This session's OWASP Web Security Agent Framework work added/modified (all
to be committed in this session's single commit — see the commit hash in
this session's final report):

- New: `docs/adr/0020-owasp-web-security-agent.md`, the full
  `core/owasp_web/` package (17 files incl. `__init__.py`/`README.md`),
  `core/parsers/http_transaction_parser.py`,
  `core/services/web_security_service.py`,
  `core/tools/web_security_tools.py`, `core/agents/web_security_agent.py`,
  one new Alembic migration, `data/sample_evidence/http_transaction.txt`,
  15 new unit test files + 2 new integration test files.
- Modified: `core/db/models/timeline_event.py`, `core/config/settings.py`,
  `.env.example`, `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`, `core/parsers/{models,registry}.py`,
  `apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
  `docs/dependency-rules.md`,
  `core/{agents,tools,parsers,services}/README.md`,
  `tests/integration/{test_api_case_routes,test_investigation_graph}.py`,
  `tests/unit/test_parsers_registry.py`, `CHANGELOG.md`, and this file.

Full suite (1395 tests), `ruff check`/`format --check`, and
`scripts/check_dependency_rules.py` all pass. `mypy core --strict` fails on
a pre-existing, unrelated numpy/environment issue (see Known Issues).

---

## Next Recommended Prompt

> Implement blueprint §7's still-open OWASP Security Agent: AST-based
> static analysis via Python's `ast` module (constitution's own quality bar,
> "never just regex") over parsed source code / API specs, mapping SQLi/
> XSS/broken-auth patterns to OWASP Top-10 2021 categories. This is the
> agent named `owasp_agent.py`/`owasp_tools.py` in blueprint §7 — **do not
> confuse it with this session's `core/owasp_web/`/`web_security_agent.py`**
> (HTTP-traffic analysis, ADR-0020), which is a separate, already-complete
> framework that must never be touched or renamed to fill this gap. This
> would finally close M4 entirely (the last five specialist-agent pieces —
> Vulnerability Assessment, Threat Hunting, Linux Security Advisor, and this
> session's out-of-blueprint Web Security Agent — are all done; only the
> blueprint-defined AST-based source-code reviewer remains open). Alternatively,
> close out M2 first with a concrete `core/agents/mitre_mapping_agent.py`
> wrapping `core.knowledge.mitre`'s existing `MitreLookup` (returning
> "unmapped" rather than a low-confidence guess when nothing matches), which
> is the one piece keeping M2's `docs/roadmap.md` checkbox open. Do **not**
> build the Incident Response Agent yet — that agent's job is case-wide
> cross-agent synthesis and depends on having more specialist agents'
> findings to actually synthesize; building it early was explicitly declined
> in a prior session as scope belonging to M5. Follow the exact three-step
> extension pattern `SocAnalystAgent`/`PhishingAgent`/
> `VulnerabilityAssessmentAgent`/`ThreatHunterAgent`/`LinuxSecurityAgent`/
> `WebSecurityAgent` all six now demonstrate: a parser/tool in its owning
> leaf package, an agent in `core/agents/` declaring a distinct capability,
> and two lines in `core/graph/investigation_graph.py`. Preserve every
> existing file and architectural decision described in this document —
> including all six specialist agents, the Case lifecycle subsystem, the
> Finding & MITRE Engine, the Vulnerability Assessment Framework, the Linux
> Security Threat Hunting Framework, the Linux Security Advisor Framework,
> and the OWASP Web Security Agent Framework — only extend them. Also worth
> addressing early in that session: the pre-existing `mypy core --strict`
> failure caused by a numpy/pandas stub incompatibility with the pinned
> `python_version = "3.11"` (see this file's Known Issues) — either pin an
> older `numpy` compatible with the target Python version, or bump the
> `pyproject.toml` mypy `python_version` if the project's actual runtime
> floor has moved past 3.11.
