# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented blueprint §7's **Linux Security Agent** (the
narrow command/permission/hardening advisor) end-to-end — an explicit ADR:
**ADR-0019, Linux Security Advisor Agent**
(`docs/adr/0019-linux-security-advisor-agent.md`). This closes the last
named piece the prior session's Linux Security Threat Hunting Framework
(ADR-0018) explicitly declined to build, adding the **fifth** concrete
specialist agent (after `SocAnalystAgent` M1, `PhishingAgent` M2,
`VulnerabilityAssessmentAgent` M4, `ThreatHunterAgent` M4), proving the same
three-step extension pattern (parser/tool in its owning leaf package, an
agent declaring a distinct capability, two lines in
`investigation_graph.py`) a fifth time — and, for the first time, a leaf
package with **no DB persistence and no enrichment-provider seam**,
matching the task's original "advisor" framing (single request in, single
`LinuxSecurityAdvice` out).

**This is not** ADR-0018's Linux Security Threat Hunting Framework
(`core/linux_security/`, SSH-auth/syslog log-based detection: brute force,
sudo abuse, privilege escalation, persistence) — that package is completely
unchanged this session; the two frameworks are deliberately separate,
never import each other, and are never to be confused. M4's other remaining
piece, the OWASP Security Agent, also remains unbuilt.

### M0/M1/M2/M3/M4 (Vulnerability Assessment, Linux Security Threat Hunting) frameworks (unchanged from prior sessions)

Configuration, logging, shared contracts, DB foundation, FastAPI app,
governance, `core/agents`/`core/tools`/`core/graph` framework,
`core/memory`/`core/knowledge` framework, `core/threat_intel` framework (20
IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine),
`Case`/`Evidence`/`Finding`/`TimelineEvent`/`Report`/`Vulnerability`/
`LinuxSecurityFindingRow` domain models, `SocAnalystAgent`, `PhishingAgent`,
`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`, `core/vulnerabilities/`
(ADR-0017), `core/linux_security/` (ADR-0018), `core/security/prompt_guard.py`,
the Case lifecycle/ownership/tags/notes/events/metrics extension (ADR-0015),
and `core/services/case_service.py`'s `investigate_new_evidence()`
orchestrator — all unchanged except where explicitly noted below.

### Linux Security Advisor Framework (new this session, ADR-0019)

- **`core/linux_advisor/`** (new leaf package, fifth peer to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`/
  `core/linux_security`, but deliberately the *lightest-weight* of the
  five — no DB persistence, no `registry.py`/`interfaces.py`
  enrichment-provider seam) —
  - `models.py`: own `LinuxAdvisorSeverity` scale (never reusing
    `core.parsers.models.Severity` or any sibling leaf's), `LinuxCommand`
    (parsed via `shlex`, `has_sudo`/`has_pipe_to_shell`/`target_paths`),
    `PermissionAnalysis` (owner/group/other rwx triplets, numeric +
    symbolic forms, special-bit flags, `ls -l` owner/group/filename),
    `CommandRisk`/`PermissionRisk` (severity, confidence, explanation,
    recommended action, matched rule ids — `severity=INFO`/no-match is a
    real, explicit "safe" outcome, never merely an absence of output),
    `HardeningRecommendation` (eight named categories, `is_baseline` flag
    distinguishing always-on baseline recs from finding-triggered ones),
    `LinuxSecurityAdvice` (the aggregate output, blueprint's exact named
    type), `RuleMatch`, `MatcherKind`.
  - `exceptions.py`: narrow hierarchy (`InvalidOctalModeError`,
    `InvalidPermissionStringError`, `InvalidSymbolicModeError`,
    `InvalidUmaskError`, `MalformedCommandError`,
    `OversizedLinuxAdvisorInputError`).
  - `rule_engine.py`: `RuleEngine`/`Rule` — a real, generic, data-driven
    detection engine, the task's named extensibility seam. `Rule.matcher`
    is a tagged union (`regex`/`literal_substring`/`callable_signature`,
    the last via `register_callable` for cross-field checks regex can't
    express). Adding a detection later means adding a `Rule` object;
    this engine's code never changes.
  - `command_rules.py`: the default dangerous-command rule set — `rm -rf`
    (root-targeting and generic), `chmod 777`/`666`, `curl`/`wget` piped
    to a shell, unrestricted sudo (`NOPASSWD: ALL`, `sudo su -`), insecure
    `chown`/`chgrp` of `/etc/shadow`/`/etc/passwd`/`/etc/sudoers`, and a
    `mkdir && chmod 777` combination check (a `callable_signature` rule).
    Every rule has a real explanation and a safer alternative.
  - `permission_parser.py`: pure functions — octal digit <-> rwx (both
    directions), 3/4-digit octal mode <-> owner/group/other + special
    bits, `ls -l` 10-char permission-string parsing (file-type + setuid/
    setgid/sticky special chars), a full `ls -l` line parser (owner/
    group/filename), symbolic `chmod` mode application against a base
    permission, and umask interpretation (default file/dir modes).
    Exhaustively tested in both directions plus every malformed-input case.
  - `command_analyzer.py`: `CommandAnalyzer` — tokenizes via `shlex.split`
    (catching `ValueError` for broken quoting, never crashing), looks up a
    deterministic command-purpose table, determines privilege requirement,
    runs the default command `RuleEngine`, returns a `CommandRisk`.
  - `permission_analyzer.py`: `PermissionAnalyzer` — flags world-writable
    files/dirs, world-writable dirs missing the sticky bit, SUID/SGID on
    shell interpreters (critical) vs. ordinary binaries (medium), and
    sensitive system files not root-owned or overly permissive.
  - `hardening_advisor.py`: `HardeningAdvisor` — finding-triggered
    recommendations (naming the specific command/path) plus a fixed
    baseline set covering all eight categories (SSH configuration, sudo
    configuration, file permissions, ownership, services, least privilege,
    filesystem security, account security), clearly distinguished via
    `is_baseline`.
  - `risk_assessment.py`: `RiskAssessmentEngine`/`LinuxAdvisorRiskWeights`
    — five configurable, sum-to-1.0-validated dimensions (highest
    individual severity, highest individual confidence, distinct finding
    count, whether any critical-category rule matched, corroboration
    across command+permission analysis), read from `Settings`.
  - `advisory_engine.py`: `LinuxSecurityAdvisoryEngine` — the orchestrator;
    classifies each line (`ls -l`-shaped -> permission path, otherwise
    command path), runs hardening + risk assessment, returns the final
    `LinuxSecurityAdvice`. Configurable oversized-input guard (max lines/
    chars, read from `Settings`), skips (never aborts on) a malformed
    line, and sanitizes control characters/embedded newlines
    (`sanitize_text`) before any analyzed text reaches a log line or the
    advice text itself — this package performs pure text analysis and
    never executes, `eval`s, or shells out to any analyzed content.
  - `metrics.py`/`audit.py`: `LinuxAdvisorMetricsCollector` (commands/
    permissions analyzed, rule matches by id, failures, timing) and
    structured audit-event emission + timing, mirroring the established
    shape in `core/vulnerabilities`/`core/linux_security`.
- **New `EvidenceType.LINUX_COMMAND_INPUT`** (`core/parsers/models.py`,
  purely additive) + **new parser `core/parsers/linux_command_parser.py`**
  (`LinuxCommandInputParser`) — one `EvidenceRecord` per non-blank line, no
  deep classification (deliberately dumb, matching every other parser in
  this package). `sniff()` gives a real, above-`PlainTextParser` (0.1)
  confidence (0.4) when it recognizes an `ls -l` permission-string prefix,
  a shebang, or a security-relevant command name. Registered in
  `core/parsers/registry.py` at priority 3, claiming `.sh`/`.cmd`/`.txt`
  extensions (`.txt` shared with `PlainTextParser` so a `.txt` upload with
  recognizable command content routes here via `sniff()`'s tie-break,
  never regressing plain-text analyst-note uploads).
- **`core/services/linux_advisor_service.py`** (new) —
  `assess_linux_command_input()`, synchronous (**no DB session
  parameter** — this framework never persists), composing
  `LinuxSecurityAdvisoryEngine` end-to-end and emitting audit events. Gets
  the documented dependency-rules exception 4g (mirrors 4e/4f, minus the
  `core/memory` edge those two have, since this module has no note-taking
  behavior).
- **`core/tools/linux_tools.py`** (`LinuxSecurityAdvisoryTool`, new) —
  blueprint's exact named file. Aggregates already-computed command/
  permission/hardening data into a case-level summary; never recomputes a
  risk/confidence score itself.
- **`core/agents/linux_security_agent.py`** (`LinuxSecurityAgent`,
  `LinuxSecurityAdvice`, new) — the fifth concrete specialist agent,
  capability `linux_security_advisory`. Deliberately thin: reads
  `CaseInvestigationState.linux_advisory_records` (new state field, plain
  `dict[str, object]` entries — deliberately a **different** field name
  from `linux_security_records`, which `ThreatHunterAgent` already uses, so
  the two frameworks' outputs never collide) and calls
  `LinuxSecurityAdvisoryTool` to produce a case-level `LinuxSecurityAdvice`
  (blueprint's exact named output type). `core/agents` has no
  dependency-rules.md import edge onto `core/linux_advisor` (identical
  reasoning to every other specialist agent's precedent).
- **`core/graph/investigation_graph.py`** (modified) — `LinuxSecurityAgent`
  registered/wired with the same two-line pattern the other four
  specialists established; module docstring updated to describe five
  agents.
- **`core/graph/state.py`** (modified) — `CaseInvestigationState` gained
  `linux_advisory_records: list[Any]` (same `operator.add` reducer shape).
- **`core/services/case_service.py`** (modified) —
  `_EVIDENCE_TYPE_CAPABILITIES` gained `LINUX_COMMAND_INPUT` ->
  `linux_security_advisory`; `_run_specialist_agents` registers the fifth
  agent and hydrates `linux_advisory_records`; `investigate_new_evidence()`
  conditionally calls `assess_linux_command_input()` (gated to
  `LINUX_COMMAND_INPUT` only, synchronous, no session) and reduces its
  already-generated `LinuxSecurityAdvice` (commands/permissions/hardening/
  summary) into plain-dict records before hydrating state, recording a
  `TimelineEvent(LINUX_ADVISORY_ASSESSED)`. `CaseInvestigationResult` gained
  `linux_advisory_count`/`highest_linux_advisory_risk_level`; new
  `_extract_linux_advisory` mirrors `_extract_threat_hunting`.
- **`core/db/models/timeline_event.py`** (modified) — new
  `TimelineEventType.LINUX_ADVISORY_ASSESSED` (a generic pipeline-stage
  marker; this framework never persists the advice itself) + one new
  Alembic migration (`a4e7c2f19b3d`) additively extending
  `timeline_event_type_enum`.
- **`apps/api/schemas.py`/`routers/evidence.py`** (modified) —
  `EvidenceUploadResponse` gained `linux_advisory_count`/
  `highest_linux_advisory_risk_level` (both `None`-defaulted, purely
  additive).
- **`core/config/settings.py`/`.env.example`** (modified) — every
  configurable threshold/weight this framework uses (max lines/chars per
  artifact, the five risk-assessment weights) — zero hardcoded values
  anywhere in `core/linux_advisor`.
- **`data/sample_evidence/linux_commands.txt`** (new fixture) — a
  `chmod 777 /var/www` line, a `curl | bash` line, an `ls -l` listing
  showing `/etc/shadow` as world-readable, and a benign `ls -la /home`
  line.
- **Testing** — 175 new tests (1302 total, up from 1127): unit tests for
  every `core/linux_advisor` module (models, rule_engine, command_rules,
  permission_parser, command_analyzer, permission_analyzer,
  hardening_advisor, risk_assessment, advisory_engine, metrics, audit —
  each with at least one adversarial/malformed-input case: a malformed
  chmod/octal value, an invalid permission string, a shell-quoting-broken
  command, an oversized-input guard, command-injection-shaped input,
  control characters/embedded newlines), the new parser (including
  registry priority/sniff behavior), the tool, the agent, an integration
  test proving the crafted fixture is detected end-to-end (dangerous
  commands flagged, safe command explicitly marked safe, hardening
  recommendations generated), an API `TestClient` test proving this
  evidence type routes to `LinuxSecurityAgent` through the real pipeline
  (`test_upload_linux_command_evidence_routes_to_linux_security_agent`),
  and a 5,000-line performance test plus an instantaneous-rejection test
  for the oversized-input guard. `test_investigation_graph.py`'s node-set
  assertion extended to the fifth agent;
  `test_parsers_registry.py`'s builtin-parser-count assertion extended to
  fifteen. mypy (`--strict` on `core/`), `ruff check`/`format`,
  `scripts/check_dependency_rules.py`, and the full pytest suite all pass.

**Explicitly NOT built, by ADR-0019's stated scope:** Log analysis, threat
hunting, SOC analysis, IOC extraction, timeline generation, finding
correlation, Incident Response, automated remediation, or LLM reasoning of
any kind anywhere in this package; a concrete `LinuxSecurityEnrichmentProvider`-
style seam (deliberately absent, unlike `core.vulnerabilities`/
`core.linux_security`); DB persistence of any kind; OWASP Security Agent
(M4's other remaining piece); MITRE Mapping Agent (M2's remaining gap); any
redesign of `SocAnalystAgent`, `PhishingAgent`, `VulnerabilityAssessmentAgent`,
`ThreatHunterAgent`, `Case`, or `core/linux_security/` (ADR-0018's separate,
already-complete framework).

---

## Repository Status

```
apps/
  api/            schemas.py (MODIFIED: +2 linux-advisor response fields) +
                   routers/{system,cases,evidence(MODIFIED: passes through
                   linux-advisor fields),iocs,findings,v1}.py             [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (MODIFIED: +7 LINUX_ADVISOR_* fields)      [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py,
                   vulnerability_agent.py, threat_hunter_agent.py
                   (unchanged) + linux_security_agent.py (NEW — fifth
                   concrete specialist agent)                             [implemented — 5 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py, vuln_tools.py,
                   linux_security_tools.py (unchanged) + linux_tools.py
                   (NEW — LinuxSecurityAdvisoryTool)                      [implemented — 5 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged)                  [implemented]
  graph/          investigation_graph.py (MODIFIED: +LinuxSecurityAgent
                   wiring) + state.py (MODIFIED: +linux_advisory_records
                   field) + routing.py/workflow_engine.py/events.py/
                   retry.py/failure_recovery.py/metrics.py (unchanged)    [implemented]
  db/             models/timeline_event.py (MODIFIED:
                   +LINUX_ADVISORY_ASSESSED) + migrations/versions/
                   (+1 NEW: extend timeline_event_type_enum) + all
                   M1/ADR-0015/0017/0018 models (unchanged)               [implemented — 11 real domain tables + 5 reference tables]
  parsers/        linux_command_parser.py (NEW — LinuxCommandInputParser)
                   + registry.py (MODIFIED: +registration) + all other
                   fourteen parsers (unchanged)                           [implemented — 15 concrete parsers]
  linux_advisor/  (NEW leaf package — models, exceptions, rule_engine,
                   command_rules, permission_parser, command_analyzer,
                   permission_analyzer, hardening_advisor, risk_assessment,
                   advisory_engine, metrics, audit)                       [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged)                                             [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +linux_advisory capability
                   routing, +_run_specialist_agents fifth agent,
                   +_extract_linux_advisory) + linux_advisor_service.py
                   (NEW — assess_linux_command_input, no DB session) +
                   evidence_service.py, threat_intel_service.py,
                   finding_service.py, vulnerability_service.py,
                   linux_security_service.py (unchanged); report_service.py [implemented]
data/             sample_evidence/linux_commands.txt (NEW fixture);
                   all other fixtures (unchanged)
scripts/          (unchanged)
tests/
  unit/           172 test modules (+15 this session:
                   test_linux_advisor_{models,rule_engine,command_rules,
                   permission_parser,command_analyzer,permission_analyzer,
                   hardening_advisor,risk_assessment,advisory_engine,
                   metrics,audit}.py, test_parsers_linux_command_parser.py,
                   test_tools_linux_tools.py,
                   test_agents_linux_security_agent.py; +1 extended:
                   test_parsers_registry.py [builtin-parser-count
                   assertion])
  integration/    12 test modules (+2 NEW:
                   test_linux_advisor_pipeline_integration.py,
                   test_linux_advisor_performance.py; +2 extended:
                   test_api_case_routes.py [linux_commands.txt upload
                   routing test], test_investigation_graph.py [node-set
                   assertion])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs + docs/adr/ (20 ADR files incl.
                   template, +0019) + docs/dependency-rules.md (MODIFIED:
                   rule 4g added, rule 5/layer-stack diagram extended) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1302 tests passing as of this session (1127 prior -> 1302 now: 175 new).
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

Fully aligned with `context/01_blueprint.md`, extending (not reversing)
ADR-0001 through ADR-0018 per ADR-0019's explicit scoping. Twelve
deliberate decisions, all documented in
`docs/adr/0019-linux-security-advisor-agent.md`:

1. **`core/linux_advisor/` is a fifth, deliberately distinct sibling leaf
   package from `core/linux_security/`** — different name, different
   input shape (freeform command/permission text vs. structured log
   events), different responsibility (advisory vs. detection), never
   importing each other.
2. **New `EvidenceType.LINUX_COMMAND_INPUT`** — purely additive.
3. **New parser `LinuxCommandInputParser`** — deliberately dumb/generic;
   deeper classification is the specialist's own job.
4. **No DB persistence, no enrichment-provider seam** — unlike
   `core/vulnerabilities`/`core/linux_security`, this task never asks for
   persisted findings or external enrichment.
5. **`LinuxAdvisorSeverity` is its own enum** — never a reuse of a sibling
   leaf's, matching the established precedent.
6. **A generic, data-driven `RuleEngine`/`Rule` seam** — the task's named
   extensibility point; adding a detection later means adding a `Rule`
   object, never touching engine code.
7. **`permission_parser.py` is pure, exhaustively bidirectional
   conversion functions** with narrow, named exceptions for every
   malformed-input path.
8. **Config-driven, no-hardcoded-values scoring** — five configurable
   dimensions, read from `Settings`, validated to sum to 1.0.
9. **`hardening_advisor.py` distinguishes finding-triggered from baseline
   recommendations** across the task's eight named categories.
10. **`advisory_engine.py` defends against three failure classes** without
    ever aborting the whole artifact: oversized input, malformed
    individual lines, and command-injection/log-injection-shaped content.
11. **`linux_tools.py`/`linux_security_agent.py` never recompute a risk/
    confidence score** — `core/agents` has no import edge onto
    `core/linux_advisor`, so state stays plain-dict-typed.
12. **No log analysis, threat hunting, SOC analysis, IOC extraction,
    timeline generation, finding correlation, Incident Response,
    remediation, or LLM reasoning anywhere in this package.**

`docs/roadmap.md` records this as a dated addendum under M4's still-open
entry (the OWASP Security Agent remains outstanding, so M4 itself stays
unchecked). No approved architectural decision (ADR-0001 through 0018) was
reversed.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **This work was scoped as blueprint §7's actual Linux Security Agent**,
  explicitly distinct from ADR-0018's Threat Hunting Agent — a new,
  differently-named package (`core/linux_advisor/`, never
  `core/linux_security/`) so the two frameworks can never be conflated.
- **No DB persistence for this framework, unlike its two prior
  siblings** — discovered while re-reading blueprint §7's original
  "advisor" framing: a single request in, a single `LinuxSecurityAdvice`
  out, no case-evidence lifecycle to track. `core/services/
  linux_advisor_service.py`'s `assess_linux_command_input()` is
  accordingly synchronous with no DB session parameter — a deliberate,
  documented deviation from every other assessment service's shape.
- **`.txt` is claimed by *both* `PlainTextParser` and
  `LinuxCommandInputParser`** — discovered while wiring the API-level
  routing test: the evidence-ingestion allowlist (`EVIDENCE_ALLOWED_EXTENSIONS`)
  doesn't include `.sh`/`.cmd`, so a `.txt` upload with genuine command
  content needed the new parser to also claim `.txt` and win the
  `sniff()`-based tie-break (`core.parsers.factory._best_sniff_match`)
  over `PlainTextParser`'s flat 0.1 confidence, without regressing
  existing plain-text analyst-note uploads (which score 0.0 against the
  new parser's `sniff()`).
- **`linux_advisory_records` is a new, separate `CaseInvestigationState`
  field**, never reusing `linux_security_records`
  (`ThreatHunterAgent`'s field) — the two frameworks' hydrated data must
  never collide on the same state key.
- **A `callable_signature` matcher kind was added to `RuleEngine`**
  alongside `regex`/`literal_substring` — discovered while designing
  `command_rules.py`'s `mkdir && chmod 777` combination check, which
  reasons about two related sub-commands joined by a shell operator, the
  kind of cross-field check a single regex expresses awkwardly.

---

## Public Interfaces

*(M0–M4/ADR-0015/0016/0017/0018 interfaces — unchanged from prior sessions
except as noted below.)*

**New/changed this session:**

`core.linux_advisor.*` (new package) —
`models.{LinuxAdvisorSeverity, HardeningCategory, RuleMatch, LinuxCommand,
PermissionAnalysis, CommandRisk, PermissionRisk, HardeningRecommendation,
LinuxSecurityAdvice, RiskDimensionScores, MatcherKind, RulePriority,
severity_rank, highest_severity}`,
`exceptions.{LinuxAdvisorError, InvalidOctalModeError,
InvalidPermissionStringError, InvalidSymbolicModeError, InvalidUmaskError,
MalformedCommandError, OversizedLinuxAdvisorInputError}`,
`rule_engine.{Matcher, Rule, RuleEngine, register_callable}`,
`command_rules.DEFAULT_COMMAND_RULES`,
`permission_parser.{octal_digit_to_rwx, rwx_to_octal_digit,
parse_octal_mode, format_octal_mode, parse_ls_permission_string,
parse_ls_line, apply_symbolic_mode, interpret_umask}`,
`command_analyzer.{CommandAnalyzer, parse_command, COMMAND_PURPOSES}`,
`permission_analyzer.{PermissionAnalyzer, SENSITIVE_SYSTEM_FILES}`,
`hardening_advisor.{HardeningAdvisor, BASELINE_RECOMMENDATIONS}`,
`risk_assessment.{RiskAssessmentEngine, LinuxAdvisorRiskWeights}`,
`advisory_engine.{LinuxSecurityAdvisoryEngine, sanitize_text}`,
`metrics.{LinuxAdvisorMetricsCollector, LinuxAdvisorMetricsSnapshot}`,
`audit.{AuditAction, log_linux_advisor_audit_event, timed_execution}`.

`core.parsers.models.EvidenceType.LINUX_COMMAND_INPUT` (new).
`core.parsers.linux_command_parser.LinuxCommandInputParser` (new).

`core.db.models.timeline_event.TimelineEventType.LINUX_ADVISORY_ASSESSED`
(new).

`core.services.linux_advisor_service.{assess_linux_command_input,
LinuxAdvisorAssessmentResult, build_linux_advisory_engine}` (new).

`core.tools.linux_tools.{LinuxSecurityAdvisoryTool,
LinuxSecurityAdvisoryInput, LinuxSecurityAdvisoryOutput,
LinuxCommandSummaryInput, LinuxPermissionSummaryInput,
LinuxHardeningSummaryInput}` (new).

`core.agents.linux_security_agent.{LinuxSecurityAgent,
default_linux_security_agent_tool_registry, LinuxSecurityAdvice,
LinuxSecurityAgentResult}` (new).

`core.graph.state.CaseInvestigationState.linux_advisory_records` (new
field). `core.graph.investigation_graph.build_investigation_graph` now
also registers/wires `LinuxSecurityAgent` (node name
`linux_security_agent`).

`core.services.case_service`: `_EVIDENCE_TYPE_CAPABILITIES` gained
`LINUX_COMMAND_INPUT -> linux_security_advisory`; `_run_specialist_agents`
gained `linux_advisory_records` parameter and registers a fifth agent; new
`_extract_linux_advisory`. `CaseInvestigationResult` gained
`linux_advisory_count`/`highest_linux_advisory_risk_level`.

`apps.api.schemas.EvidenceUploadResponse` gained
`linux_advisory_count`/`highest_linux_advisory_risk_level` (both optional,
default `None`).

`core.config.Settings` gained 7 new fields:
`linux_advisor_max_lines_per_artifact`,
`linux_advisor_max_chars_per_artifact`, five
`linux_advisor_risk_weight_*` fields.

No OWASP/Incident Response/MITRE Mapping Agent, LLM reasoning,
`/api/v1/reports` route, or `core.security.{pii_redaction,approval_gate}`
implementation exist as public interfaces yet.

---

## Remaining Work

1. **M2 — still open.** A concrete `core/agents/mitre_mapping_agent.py`
   wrapping `core.knowledge.mitre`'s lookup engine.
2. **M3 — closed** (prior session).
3. **M4 — remaining piece.** OWASP Security Agent (AST-based, not regex —
   constitution's own quality bar). The blueprint §7 Linux Security Agent
   is now **closed** (this session).
4. **M5 — Incident Response synthesis + Reporting.** Incident Response
   Agent (the correct home for cross-agent recommendation/escalation/
   remediation synthesis — still not built, by design), Report Generator
   Agent, Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports`
   route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB,
   populate remaining knowledge data (OWASP, playbooks), the real
   cross-evidence Threat Timeline UI feature, MITRE heatmap/AI Analyst
   Chat UI.
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** `core/security/pii_redaction.py`/
   `approval_gate.py`; a structured read endpoint for `Case.labels`; a
   concrete `LinuxSecurityEnrichmentProvider`/`VulnerabilityEnrichmentProvider`
   (e.g. a live IP-reputation/NVD API lookup — `core/linux_advisor` has no
   such seam at all, by design); CVSS v4.0 base-score computation; a real
   journald-field mapping in `core/parsers/field_heuristics.py`;
   reconciling `SocFinding`/`PhishingVerdict`/`VulnerabilityFinding`/
   `LinuxSecurityFinding`/`LinuxSecurityAdvice` (all in-memory only) with
   the persisted `Finding` table into one shared representation; an
   asset-criticality inventory.

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist;
`apps/web` has no code; harmless Starlette deprecation warnings in test
output; no CI has ever actually run on GitHub;
`scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import
rule, not the full sibling-layer matrix; `InMemoryVectorStore` is O(n)
brute-force; `HashingTextEmbedder` is not semantic; numpy not installed;
`windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`;
`SocAnalystAgent`'s/`PhishingAgent`'s/`VulnerabilityAssessmentAgent`'s/
`ThreatHunterAgent`'s finding output is still not persisted to the
`findings` table; `Report` still has no consumer; on PostgreSQL,
downgrading the `CaseStatus`/`timeline_event_type` enum-extension
migrations is a no-op; `Case.labels` has no read endpoint; no case-level
authorization/ownership check; the duplicate-case guard is intentionally
narrow; CVSS v4.0 is vector-validation-only; multi-CVE scan findings fold to
their first CVE; no asset-criticality inventory exists.)*

- **`LinuxSecurityAdvice` (this session's output type) is never persisted
  anywhere** — by design (ADR-0019 point 3), not a gap to close later; the
  same is true of `SocFinding`/`PhishingVerdict`/`VulnerabilityFinding`/
  `LinuxSecurityFinding`, which *are* deferred gaps.
- **`core/linux_advisor` has no enrichment-provider seam at all** —
  unlike `core/vulnerabilities`/`core/linux_security`'s unimplemented-but-
  present `registry.py`/`interfaces.py`, this package doesn't even define
  the seam, since the task never called for external enrichment.
- **`apply_symbolic_mode`'s conditional-execute (`X`) support is
  simplified** — treated as plain `x` regardless of the target's existing
  execute bit, since this package never inspects a real filesystem to know
  whether any execute bit is already set. Documented in the function's own
  docstring.
- **`_EVIDENCE_TYPE_CAPABILITIES` in `case_service.py` is a simple dict of
  tuples**, not a general routing engine — unchanged limitation, carried
  forward.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`core/linux_advisor` is pure Python (stdlib `re`/`shlex`) plus Pydantic,
reusing the already-vendored parser layer.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the Linux Security Threat Hunting Framework
(ADR-0018) commit is committed.

This session's Linux Security Advisor Framework work added/modified (all
committed in this session's single commit — see the commit hash in this
session's final report):

- New: `docs/adr/0019-linux-security-advisor-agent.md`, the full
  `core/linux_advisor/` package (13 files incl. `__init__.py`/`README.md`),
  `core/parsers/linux_command_parser.py`,
  `core/services/linux_advisor_service.py`,
  `core/tools/linux_tools.py`, `core/agents/linux_security_agent.py`, one
  new Alembic migration, `data/sample_evidence/linux_commands.txt`, 15 new
  unit test files + 2 new integration test files.
- Modified: `core/db/models/timeline_event.py`, `core/config/settings.py`,
  `.env.example`, `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`, `core/parsers/{models,registry}.py`,
  `apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
  `docs/dependency-rules.md`,
  `core/{agents,tools,parsers,services}/README.md`,
  `tests/integration/{test_api_case_routes,test_investigation_graph}.py`,
  `tests/unit/test_parsers_registry.py`, `CHANGELOG.md`, and this file.

Full suite (1302 tests), `ruff check`/`format`, `mypy core --strict`, and
`scripts/check_dependency_rules.py` all pass.

---

## Next Recommended Prompt

> Implement M4's last remaining piece: the OWASP Security Agent (AST-based
> static analysis via Python's `ast` module — constitution's own quality
> bar, "never just regex" — mapping SQLi/XSS/broken-auth patterns to OWASP
> Top-10 2021, per blueprint §7). This closes M4 entirely (the blueprint §7
> Linux Security Agent piece is now done — this session's
> `core/linux_advisor/` framework). Alternatively, close out M2 first with
> a concrete `core/agents/mitre_mapping_agent.py` wrapping
> `core.knowledge.mitre`'s existing `MitreLookup` (returning "unmapped"
> rather than a low-confidence guess when nothing matches), which is the
> one piece keeping M2's `docs/roadmap.md` checkbox open. Do **not** build
> the Incident Response Agent yet — that agent's job is case-wide
> cross-agent synthesis (recommendations, escalation, remediation) and
> depends on having more specialist agents' findings to actually
> synthesize; building it early was explicitly declined in a prior session
> as scope belonging to M5. Follow the exact three-step extension pattern
> `SocAnalystAgent`/`PhishingAgent`/`VulnerabilityAssessmentAgent`/
> `ThreatHunterAgent`/`LinuxSecurityAgent` all five now demonstrate: a
> parser/tool in its owning leaf package, an agent in `core/agents/`
> declaring a distinct capability, and two lines in
> `core/graph/investigation_graph.py`. Preserve every existing file and
> architectural decision described in this document — including all five
> specialist agents, the Case lifecycle subsystem, the Finding & MITRE
> Engine, the Vulnerability Assessment Framework, the Linux Security Threat
> Hunting Framework, and the Linux Security Advisor Framework — only extend
> them.
