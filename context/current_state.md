# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session closed **Milestone M2's remaining named piece** (email parser,
prompt-injection guard, Phishing Investigation Agent) and, as a direct
consequence, **Milestone M3's own demo criterion** (real Coordinator fan-out
to two real specialist agents) — per an explicit ADR: **ADR-0016, Phishing
Investigation Agent, Email Parser, Prompt Guard**
(`docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`). A prior
request in this same session asked for a ground-up "complete SOC Analyst
Agent" implementation; that request was flagged as a conflict before any code
was written — `SocAnalystAgent` is production, M1-closed, scoped narrowly per
blueprint §7 ("the generalist log analyst"), and the requested case-wide
IOC/threat-intel/finding-review-with-recommendation-and-escalation-engine
scope belongs to the Incident Response Agent (M5), not the SOC Analyst Agent
— and was also internally self-contradictory (it asked for escalation/
containment recommendations while explicitly excluding the Incident Response
Agent). The user confirmed: do not touch `SocAnalystAgent`; implement the
next actually-queued roadmap item instead.

### M0/M1/M2(MITRE)/M3(framework)/M4(threat-intel)/M6 frameworks (unchanged from prior sessions)

Configuration, logging, shared contracts, DB foundation, FastAPI app,
governance, `core/agents`/`core/tools`/`core/graph` framework,
`core/memory`/`core/knowledge` framework, `core/threat_intel` framework (20
IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine),
`Case`/`Evidence`/`Finding`/`TimelineEvent`/`Report` domain models,
`SocAnalystAgent`, `core/services/case_service.py`'s (now-generalized)
`investigate_new_evidence()` orchestrator, the first `/api/v1` routes, and
the full Case lifecycle/ownership/tags/notes/events/metrics extension
(ADR-0015) — all unchanged except where explicitly noted below.

### Phishing Investigation Agent, Email Parser, Prompt Guard (new this session, ADR-0016)

- **`core/parsers/email_parser.py`** (new) — `EmailParser`, using only the
  stdlib `email` package (`message_from_string` + `policy.default`; no new
  dependency). Decodes an RFC 5322 message into a header `EvidenceRecord`
  (sender/reply-to/subject/to as plain text in `raw_line`, so the existing
  `IOCExtractionEngine` regex-scan finds sender/URL/domain IOCs with zero new
  extraction code) and a body `EvidenceRecord`. Extracts attachment
  filenames/content-types into `NormalizedEvidence.metadata`. Never extracts
  IOCs or renders a verdict itself. New additive `EvidenceType.EMAIL`;
  registered in `default_parser_registry()`; `.eml` added to
  `Settings.evidence_allowed_extensions`/`.env.example`; a lightweight
  `sniff_evidence_type` heuristic added to `core/parsers/detection.py` for
  content-sniff fallback.
- **`core/security/prompt_guard.py`** (new) — the first concrete
  `core/security` implementation. `scan_text()`: deterministic,
  pattern-based detection across four categories (instruction-override,
  role-override, exfiltration, obfuscation), never an LLM call. Zero
  outbound `core/` dependency except `core/config` (uses the already-
  scaffolded, previously-unused `Settings.prompt_guard_extra_pattern_list`
  for operator-supplied additions). Documented as a heuristic layer, not a
  guarantee.
- **`core/tools/phishing_tools.py`** (new) — `PhishingScoringTool` +
  `PhishingScoringWeights`. Deterministic sender/reply-to domain-mismatch
  check, urgency/social-engineering phrase-density scan, high-risk
  attachment-extension check, combined with the case's already-scored
  attributed URL/domain/email IOC composite scores (never re-extracted or
  re-scored) into an independent 0-100 risk scale + `Severity` label,
  distinct from `core.tools.scoring.RiskScoringTool`'s raw-log scale.
- **`core/agents/phishing_agent.py`** (new) — `PhishingAgent`, the second
  concrete specialist agent, capability `email_triage`. Screens email
  subject/body through `prompt_guard.scan_text` *before* using that text for
  anything else (the first agent in the codebase consuming attacker-
  controlled text). Reads `CaseInvestigationState.extracted_indicators` as
  plain `dict[str, object]` entries, deliberately not a typed
  `core.threat_intel.models.ScoredIOC` import (`docs/dependency-rules.md`
  rule 4 grants `core/agents` no import edge onto `core/threat_intel`).
  Produces `PhishingVerdict[]`, appended to `CaseInvestigationState.findings`
  — not persisted to the `findings` DB table, matching ADR-0014 point 4's
  identical scoping decision for `SocFinding`.
- **`core/graph/investigation_graph.py`** (modified) — `PhishingAgent`
  registered/wired with the same two-line pattern (`add_agent_node`/
  `add_edge(..., END)`) `SocAnalystAgent` established; a new
  `_ensure_phishing_agent_registered` mirrors `_ensure_soc_analyst_registered`.
- **`core/services/case_service.py`** (modified) — `_run_soc_analysis`
  generalized to `_run_specialist_agents`: registers both concrete specialist
  agents in the fresh per-run `AgentRegistry` and computes
  `required_capabilities` from the newly-ingested artifact's `EvidenceType`
  via a new `_required_capability_for` table (`EMAIL` -> `email_triage`,
  everything else -> `log_analysis`, preserving prior behavior for every
  existing log-shaped format — a real, regression-tested behavior change to
  an already-shipped internal function, not just an addition). New
  `_hydrate_attributed_iocs` reads the case's persisted `IOC` rows
  (`core.db.ioc_repository.IOCRepository.find_by_evidence`, a normal
  services-\>db edge needing no new dependency-rule exception) and reduces
  each to a plain dict before hydrating `CaseInvestigationState.
  extracted_indicators`. `CaseInvestigationResult` gained
  `phishing_risk_score`/`phishing_risk_label`; new `_extract_phishing_risk`
  mirrors `_extract_soc_risk`.
- **`apps/api/schemas.py`/`apps/api/routers/evidence.py`** (modified) —
  `EvidenceUploadResponse` gained `phishing_risk_score`/`phishing_risk_label`
  (both `None`-defaulted, purely additive, no `/api/v2` cutover). No router
  changes were needed for `.eml` dispatch — the existing parser factory's
  extension/content-sniff selection already routes it.
- **Testing** — 45 new tests (821 total, up from 776): parser unit tests
  (phishing/legitimate fixtures, malformed-input degradation, attachment
  metadata), prompt-guard unit tests (adversarial injection fixtures across
  all four categories, operator-pattern-override, determinism), phishing-
  tools unit tests (each heuristic in isolation, combined scoring,
  clamping), agent-contract tests (no-evidence degradation, non-email-
  evidence skip, benign-vs-phishing scoring, prompt-injection detection,
  attributed-IOC-score attribution, malformed-entry skip), an integration
  test proving an `.eml` upload routes to `PhishingAgent` (not
  `SocAnalystAgent`) with its IOCs correctly attributed, a companion
  legitimate-email low-risk test, a regression test proving the existing
  SOC-only log-upload path is unchanged, and an API `TestClient` test
  proving the single `POST /evidence` endpoint dispatches `.eml` uploads
  with zero router changes. mypy (`--strict` on `core/`), `ruff check`/
  `format`, `scripts/check_dependency_rules.py`, and the full pytest suite
  all pass.

**Explicitly NOT built, by ADR-0016's stated scope:** LLM reasoning of any
kind (no LLM client wrapper exists anywhere in this codebase yet); a MITRE
Mapping Agent (M2 stays unchecked in `docs/roadmap.md` until one exists);
the Incident Response Agent or any cross-case/case-wide recommendation-
and-escalation engine (that request was explicitly declined this session,
see "Key Decisions"); `Nessus`/`OpenVAS`/source-code/incident-note parsers;
`core/security/pii_redaction.py`/`approval_gate.py`; any redesign of
`SocAnalystAgent`, `Case`, or any other already-completed module.

---

## Repository Status

```
apps/
  api/            FastAPI app + schemas.py (MODIFIED: +2 phishing
                   response fields) +
                   routers/{system,cases,evidence(MODIFIED: passes
                   through phishing fields),iocs,findings,v1}.py       [implemented]
  web/             Streamlit frontend                                  [README only]
core/
  config/         settings.py (MODIFIED: +.eml to allowed extensions)  [implemented]
  logging/        (unchanged)                                          [implemented]
  exceptions.py, schemas.py, interfaces.py (unchanged)                 [implemented]
  agents/         coordinator.py, planning_agent.py, registry.py,
                   base.py, confidence.py, contracts.py (unchanged) +
                   soc_analyst_agent.py (unchanged) +
                   phishing_agent.py (NEW — PhishingAgent, second
                   concrete specialist agent)                          [implemented — 2 concrete specialist agents]
  tools/          base.py, registry.py, scoring.py (unchanged) +
                   phishing_tools.py (NEW — PhishingScoringTool)        [implemented — 2 concrete tools]
  memory/         (unchanged)                                          [implemented — framework only]
  knowledge/      (unchanged)                                          [implemented]
  graph/          investigation_graph.py (MODIFIED: +PhishingAgent
                   wiring) + state.py/routing.py/workflow_engine.py/
                   events.py/retry.py/failure_recovery.py/metrics.py/
                   execution_context.py (unchanged)                    [implemented]
  db/             ioc_repository.py (unchanged, now also called
                   directly from case_service.py) + all M1/ADR-0015
                   models/repositories (unchanged)                     [implemented — 9 real domain tables + 5 reference tables]
  parsers/        models.py (MODIFIED: +EvidenceType.EMAIL) +
                   detection.py (MODIFIED: +email content-sniff
                   heuristic) + registry.py (MODIFIED: +EmailParser
                   registration) + email_parser.py (NEW) + the nine
                   M1 parsers (unchanged)                               [implemented — 10 concrete parsers]
  threat_intel/   (unchanged)                                           [implemented]
  findings/       (unchanged)                                           [implemented]
  security/       prompt_guard.py (NEW — scan_text, PromptGuardResult,
                   PromptInjectionCategory); pii_redaction.py,
                   approval_gate.py still not started                   [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                 [not started]
  services/       case_service.py (MODIFIED: _run_soc_analysis ->
                   _run_specialist_agents, +_hydrate_attributed_iocs,
                   +_extract_phishing_risk, +_required_capability_for
                   table) + case_lifecycle.py/case_events.py/
                   case_metrics.py (unchanged) +
                   evidence_service.py, threat_intel_service.py,
                   finding_service.py (unchanged); report_service.py     [implemented]
data/             sample_evidence/{phishing_sample_01,
                   legitimate_sample_01}.eml now consumed by tests
                   (pre-existing fixtures, unchanged)
scripts/          (unchanged)
tests/
  unit/           115 test modules (+4 this session:
                   test_parsers_email.py, test_security_prompt_guard.py,
                   test_tools_phishing_tools.py, test_agents_phishing.py;
                   +1 existing test renamed/extended:
                   test_parsers_registry.py)
  integration/    7 test modules (+2 extended this session:
                   test_case_service_pipeline.py, test_api_case_routes.py,
                   test_investigation_graph.py [one test renamed])
  golden/         (empty — no report generation exists yet)
docs/             17 markdown docs (roadmap.md addendum) +
                   docs/adr/ (17 ADR files incl. template, +0016) +
                   docs/dependency-rules.md (MODIFIED: rule 4d extended) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

821 tests passing as of this session (776 prior → 821 now: 45 new). Modified
this session: `core/parsers/{models,detection,registry}.py`,
`core/config/settings.py`, `.env.example`, `core/agents/README.md`,
`core/tools/README.md`, `core/parsers/README.md`, `core/security/README.md`,
`core/graph/investigation_graph.py`, `core/services/case_service.py`,
`apps/api/{schemas,routers/evidence}.py`, `docs/roadmap.md`,
`docs/dependency-rules.md`, `tests/unit/test_parsers_registry.py`,
`tests/integration/{test_case_service_pipeline,test_api_case_routes,
test_investigation_graph}.py`, `CHANGELOG.md`, and this file — all currently
uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing)
ADR-0001 through ADR-0015 per ADR-0016's explicit scoping. Nine deliberate
decisions, all documented in
`docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`:

1. **`EvidenceType.EMAIL` is additive** — nine prior values unchanged.
2. **`EmailParser` uses only the stdlib `email` package** — no new
   dependency; not `eml_parser`.
3. **`EmailParser` never extracts IOCs or renders a verdict** — it only
   produces structure; the existing `IOCExtractionEngine` already handles
   extraction over its `raw_line` output.
4. **`prompt_guard.py` is deterministic pattern-matching, not an LLM call**
   — a guard manipulable by the text it screens would defeat its purpose.
5. **`PhishingAgent` never re-extracts IOCs or recomputes threat scores** —
   `PhishingScoringTool` only aggregates what `core/threat_intel` already
   computed, on its own independent 0-100 scale.
6. **`CaseInvestigationState.extracted_indicators` entries stay plain
   dicts, not typed `ScoredIOC`** — `core/agents` has no dependency-rules.md
   import edge onto `core/threat_intel`; `core/graph/state.py` already
   defers that narrowing to a future Threat Hunting Agent milestone.
7. **Per-artifact capability routing replaces the SOC-only hardcode** in
   `case_service.py` — a real, regression-tested behavior change to an
   already-shipped internal function, closing M3's own demo criterion.
8. **`PhishingVerdict` is not persisted to `findings`** — matches ADR-0014
   point 4's identical scoping decision for `SocFinding`.
9. **`EvidenceUploadResponse` gains two fields purely additively** — no
   `/api/v2` cutover needed.

`docs/roadmap.md` records this as a dated addendum under M2's still-open
entry (MITRE Mapping Agent remains outstanding, so M2 itself stays
unchecked) and checks off M3 (its demo criterion is now genuinely met with
real agents, not test doubles). No approved architectural decision
(ADR-0001 through 0015) was reversed.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **A "rebuild the complete SOC Analyst Agent from scratch" framing was
  flagged as a conflict before any code was written, not built as
  requested.** `SocAnalystAgent` is production, M1-closed, scoped narrowly
  to blueprint §7's "generalist log analyst" definition. The requested
  scope (case-wide IOC/threat-intel/finding review, a recommendation engine
  with Contain/Isolate/Escalate outputs, executive summaries) belongs to the
  Incident Response Agent (blueprint §7, M5), not the SOC Analyst Agent, and
  was also self-contradictory (it required Incident-Response-Agent-shaped
  reasoning while explicitly excluding building the Incident Response
  Agent). The user confirmed this reframing and redirected to the actually-
  queued M2 item instead.
- **`EmailParser` never extracts IOCs itself** — this was the key design
  insight that kept the new agent's footprint minimal: putting sender/
  reply-to/URL text into `EvidenceRecord.raw_line` is sufficient for the
  *existing* `IOCExtractionEngine` to find them, with zero new extraction
  code, directly honoring "never reimplement IOC extraction."
- **`extracted_indicators` stays untyped (plain dicts) rather than
  introducing a `core.threat_intel.models.ScoredIOC` import into
  `core/agents`** — discovered mid-implementation by re-checking
  `docs/dependency-rules.md` rule 4 (which lists `core/tools`, `core/parsers`,
  `core/knowledge`, `core/memory`, `core/security`, and `core/graph/state.py`
  as `core/agents`'s allowed imports — `core/threat_intel` is conspicuously
  absent, reserved for `core/services/{threat_intel_service,finding_service}.py`'s
  own narrow exceptions 4b/4c). `core/services/case_service.py` reduces
  persisted `IOC` rows to plain dicts before hydrating state instead.
- **`case_service._run_soc_analysis` was generalized, not left alongside a
  new parallel `_run_phishing_analysis`** — a single `_run_specialist_agents`
  registers both agents and computes one `required_capabilities` list from
  the artifact's `EvidenceType`, avoiding two near-duplicate orchestration
  functions and matching the Coordinator/Planning Agent's existing
  capability-matching design intent.

---

## Public Interfaces

*(M0–M4/M6/ADR-0015 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session:**

`core.parsers.models.EvidenceType.EMAIL` (new). `core.parsers.email_parser.EmailParser`
(new). `core.security.prompt_guard.{scan_text, PromptGuardResult,
PromptInjectionMatch, PromptInjectionCategory}` (new).
`core.tools.phishing_tools.{PhishingScoringTool, PhishingScoringInput,
PhishingScoringOutput, PhishingScoringWeights, classify_phishing_risk,
sender_reply_to_mismatch, count_urgency_phrases, high_risk_attachments}`
(new). `core.agents.phishing_agent.{PhishingAgent,
default_phishing_agent_tool_registry, PhishingVerdict,
PhishingAnalysisResult}` (new).

`core.graph.investigation_graph.build_investigation_graph` now also
registers/wires `PhishingAgent` (node name `phishing_agent`).

`core.services.case_service`: `_run_soc_analysis` renamed/generalized to
`_run_specialist_agents` (now takes `evidence_id`, registers both agents,
computes capability from `EvidenceType`); new `_hydrate_attributed_iocs`,
`_extract_phishing_risk`, `_required_capability_for`. `CaseInvestigationResult`
gained `phishing_risk_score`/`phishing_risk_label`.

`apps.api.schemas.EvidenceUploadResponse` gained `phishing_risk_score`/
`phishing_risk_label` (both optional, default `None`).

No Incident Response Agent, Vulnerability/OWASP/Linux Security/Threat
Hunting/MITRE Mapping Agent, LLM reasoning, `/api/v1/reports` route, or
`core.security.{pii_redaction,approval_gate}` implementation exist as public
interfaces yet.

---

## Remaining Work

1. **M2 — still open.** A concrete `core/agents/mitre_mapping_agent.py`
   wrapping `core.knowledge.mitre`'s lookup engine — this is the one piece
   keeping M2's checkbox unchecked (the MITRE knowledge layer and Finding &
   MITRE Engine themselves were already built ahead of schedule).
2. **M3 — closed this session.**
3. **M4 — remaining piece.** Vulnerability Assessment Agent (+ Nmap/Nessus/
   OpenVAS parsers + CVSS calculator), OWASP Security Agent, Linux Security
   Agent, `core/agents/threat_hunter_agent.py`.
4. **M5 — Incident Response synthesis + Reporting.** Incident Response
   Agent (the correct home for cross-agent recommendation/escalation
   synthesis — explicitly not built this session, see "Key Decisions"),
   Report Generator Agent, Jinja2/ReportLab templates, Plotly charts,
   `/api/v1/reports` route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB,
   populate remaining knowledge data (OWASP, playbooks), Threat Timeline/
   MITRE heatmap/AI Analyst Chat UI.
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** `core/security/pii_redaction.py`/
   `approval_gate.py`; a structured read endpoint for `Case.labels`;
   reconciling constitution §7's `relationship()`/`back_populates` text with
   the codebase's uniform FK-column pattern; reconciling `SocFinding`/
   `PhishingVerdict` (in-memory only) with the persisted `Finding` table
   into one shared representation.

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist;
`apps/web` has no code; harmless Starlette deprecation warnings in test
output; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py`
only checks the streamlit/fastapi-import rule, not the full sibling-layer
matrix; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is
not semantic; numpy not installed; `windows_event_parser.py` handles only
CSV/XML export, not binary `.evtx`; `SocAnalystAgent`'s `SocFinding[]`
output is still not persisted to the `findings` table, per ADR-0014 point 4;
`Report` still has no consumer; on PostgreSQL, downgrading the `CaseStatus`
enum-extension migration is a no-op; `Case.labels` has no read endpoint; no
case-level authorization/ownership check; the duplicate-case guard is
intentionally narrow.)*

- **`PhishingVerdict` is also not persisted to `findings`**, the identical
  gap `SocFinding` already had (ADR-0014 point 4) — now two specialist
  agents' outputs live only in `CaseInvestigationState`/in-process
  `AgentExecutionResult`, not the DB. Reconciling both into one shared,
  `source_agent`-tagged persisted representation remains explicitly
  deferred, not decided by default.
- **`EmailParser` decodes from a single text representation** (matching
  every other parser in this package) — a genuinely multipart MIME message
  with per-part, non-UTF-8 charsets may not decode every part correctly. A
  documented, real limitation, not a defect masked as one.
- **`prompt_guard.py` is a heuristic, signature-based defense layer, not a
  guarantee** — a sufficiently novel injection phrasing may not match any
  pattern. Documented in `core/security/README.md`, not silently overstated.
- **`_required_capability_for`'s evidence-type-to-capability table is a
  simple dict**, not a general routing/rules engine — adding a third
  specialist agent needing multi-capability or content-based (not just
  `EvidenceType`-based) routing will need a small design decision, not
  automatically fall out of the current shape.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** —
`EmailParser` uses only the stdlib `email` package.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work (through the ADR-0015 Case Management Extension) is
committed.

This session's Phishing Investigation Agent / Email Parser / Prompt Guard
work added/modified (all currently uncommitted):
- New: `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`,
  `core/parsers/email_parser.py`, `core/security/prompt_guard.py`,
  `core/tools/phishing_tools.py`, `core/agents/phishing_agent.py`, 4 new
  test files (`tests/unit/test_parsers_email.py`,
  `tests/unit/test_security_prompt_guard.py`,
  `tests/unit/test_tools_phishing_tools.py`,
  `tests/unit/test_agents_phishing.py`).
- Modified: `core/parsers/{models,detection,registry}.py`,
  `core/config/settings.py`, `.env.example`, `core/graph/investigation_graph.py`,
  `core/services/case_service.py`, `apps/api/{schemas,routers/evidence}.py`,
  `docs/roadmap.md`, `docs/dependency-rules.md`, `core/agents/README.md`,
  `core/tools/README.md`, `core/parsers/README.md`, `core/security/README.md`,
  `tests/unit/test_parsers_registry.py`,
  `tests/integration/{test_case_service_pipeline,test_api_case_routes,
  test_investigation_graph}.py`, `CHANGELOG.md`, `context/current_state.md`
  (this file).

Full suite (821 tests), `ruff check`/`format`, `mypy core --strict`, and
`scripts/check_dependency_rules.py` all pass. Commit only when the user
explicitly asks.

---

## Next Recommended Prompt

> Implement Milestone M2's one remaining piece: a concrete
> `core/agents/mitre_mapping_agent.py` wrapping `core.knowledge.mitre`'s
> existing `MitreLookup` — blueprint §7's MITRE Mapping Agent, "used by
> SOC/Threat Hunting/Incident agents" to map a described behavior to a
> MITRE technique ID with tactic/phase, returning "unmapped" rather than a
> low-confidence guess when nothing matches. This closes M2's checkbox in
> `docs/roadmap.md`. Alternatively, if M4's breadth is preferred instead:
> the Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS
> calculator per `core/knowledge/cvss_calculator.py`, unbuilt), OWASP
> Security Agent (AST-based, not regex — constitution's own quality bar),
> and Linux Security Agent are the next three specialist agents in
> priority order, following the exact three-step extension pattern
> `SocAnalystAgent`/`PhishingAgent` both now demonstrate: a parser/tool in
> its owning leaf package, an agent in `core/agents/` declaring a distinct
> capability, and two lines in `core/graph/investigation_graph.py`. Do
> **not** build the Incident Response Agent yet — that agent's job is
> case-wide cross-agent synthesis (recommendations, escalation,
> containment/eradication/recovery) and depends on having more than two
> specialist agents' findings to actually synthesize; building it early
> was explicitly declined this session as scope belonging to M5. Preserve
> every existing file and architectural decision described in this
> document — including `SocAnalystAgent`, `PhishingAgent`, the Case
> lifecycle/ownership/tags/notes/events/metrics subsystem, and the Finding
> & MITRE Engine — only extend them.
