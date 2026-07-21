# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Most recent session:** a follow-up task asked for this same AI
Investigation Assistant backend again (a differently-worded, thirteen-
component spec). A pre-implementation check (per this project's own
"never redesign completed modules" rule and constitution §14.9) confirmed
the ten-component pipeline below was already fully built, tested, and
live behind `POST /api/v1/cases/{case_id}/conversation` — presented to the
user as a conflict via `AskUserQuestion` rather than silently rebuilt.
The user chose to close only the two genuine gaps: **Response Validator**
(new `core/conversation/response_validator.py` — makes the
grounding/anti-hallucination guarantee, previously implicit inside
`CitationEngine`/`TemplateChatModelProvider`, an explicit, independently
testable `ResponseValidationResult` check, wired into
`ResponseOrchestrator`/`ConversationManager` with a new audit action and
metrics counter) and **Conversation Events** (determined to already be
satisfied by the existing `audit.py`, no new module added). See
`docs/adr/0025-ai-investigation-assistant-conversational-interface.md`'s
"Addendum" section for the full decision record. 6 new tests plus extended
orchestrator/manager/metrics/models tests — full suite now **1712 tests**
(up from 1704); `ruff check`/`format --check`, `mypy --strict` on
`core/conversation`, and `scripts/check_dependency_rules.py` all pass.
Nothing else in `core/conversation`, `core/services/conversation_service.py`,
or the API route was changed.

---

Prior session implemented blueprint §13's **AI Investigation Assistant
(Conversational Interface)** — the AI Analyst Chat's backend orchestration
(`docs/adr/0025-ai-investigation-assistant-conversational-interface.md`), a
task brief naming ten required components: Conversation Manager, Session
Manager, Conversation Memory, Context Builder, Prompt Builder, Retrieval
Layer, Tool Selection Engine, Response Orchestrator, Citation Engine,
Conversation Audit Log. This is **further progress on M6** (roadmap already
records M6's Memory & Knowledge Layer infrastructure as built ahead of
schedule under ADR-0010; this session builds the chat feature itself on top
of it) — not a new milestone closure, since M6's own demo criterion (a real
ChromaDB backend, populated MITRE/OWASP knowledge, a real LLM-backed
`ChatModelProvider`, and the `apps/web` chat UI) still isn't met.

**Before writing any code**, this session checked for existing
infrastructure per constitution §14.9 ("never duplicate functionality") and
found most of the generic memory plumbing this feature needs **already
built**: ADR-0010 (two sessions prior) had already shipped
`core.memory.conversation_memory.ConversationMemory`/
`InMemoryConversationMemory` (case-scoped chat turn storage) and
`core.memory.context_builder.ContextBuilder` (generic filter/dedup/rank/
truncate assembly), specifically anticipating this feature. This session
reuses both directly rather than rebuilding a second conversation store or
a second generic ranking algorithm — see `docs/adr/0025`'s Decision 1 for
the resulting, slightly unusual dependency shape (see below).

A real architecture question was resolved before writing any code (no
`AskUserQuestion` needed — the task brief itself and blueprint §13's own
wording left only one reasonable answer, unlike ADR-0022's/ADR-0024's
genuine two-way forks): every existing `core/` leaf package
(`core/tools`, `core/reporting`, `core/incident_response`, ...) is
explicitly forbidden from importing `core/memory` (`docs/dependency-
rules.md` rule 5) — but this assistant's entire purpose is to sit on top of
`ConversationMemory`. Resolution: `core/conversation` stays a pure,
`core/memory`-free leaf exactly like the others (it only ever receives
already-fetched case data and conversation history as plain data); the one
new module that needs `core/memory` (plus `core/db` for retrieval and
`core/security` for prompt-injection screening) is a new, on-demand
`core/services/conversation_service.py`, via a new, documented
dependency-rules.md exception (**rule 4j**, worded identically to the
already-established 4a-4i family). This is the same "on-demand service, not
a graph node" shape ADR-0024 offered as an alternative for the Report
Generator Agent — the obviously correct shape here, since the AI Analyst
Chat is explicitly a user-triggered, on-demand action, never part of the
automatic per-upload investigation pipeline.

**What this session actually built:**
- **`core/conversation/`** (new leaf package, eleventh peer to
  `core/threat_intel`/`core/findings`/`core/vulnerabilities`/
  `core/linux_security`/`core/linux_advisor`/`core/owasp_web`/
  `core/owasp_security`/`core/incident_response`/`core/reporting` —
  though, uniquely among them, deliberately `core/memory`-free by
  necessity rather than by "doesn't happen to need it," see above) —
  - `models.py`: `ConversationRetrievalContext` (the normalized input every
    upstream case-data source is reduced to, mirroring `core.reporting.
    inputs.ReportGenerationContext`'s role exactly), `EvidenceCategory`,
    `RetrievedItem`/`SourceReference`, `ToolSelection`,
    `AssembledConversationContext`, `ConversationHistoryTurn`,
    `PromptPayload`, `ChatCompletion`, `ConversationAnswer`,
    `ConversationSession`, `AuditEventAction`/`ConversationAuditEvent`.
  - `exceptions.py`: narrow hierarchy (`ConversationError`,
    `EmptyQuestionError`, `OversizedConversationInputError`).
  - `retrieval.py`: `RetrievalLayer` — the task's named "Retrieval Layer";
    deterministic keyword-overlap relevance scoring (not semantic/embedding
    search — a documented, honest scope boundary for a future upgrade
    behind the same `RetrievedItem` shape) of already-hydrated Findings/
    IOCs/MITRE mappings/Reports/Timeline events against a question, with an
    oversized-input guard per category and skip-on-malformed defense
    (never crashing on a non-dict entry).
  - `tool_selection.py`: `ToolSelectionEngine` — the task's named "Tool
    Selection Engine"; deterministic keyword routing from question text to
    which `EvidenceCategory` values apply, falling back to searching every
    category when no keyword matches (never silently answering from a
    narrower slice than intended).
  - `context_builder.py`: `ConversationContextBuilder` — the task's named
    "Context Builder"; rank-by-relevance then budget-truncate, a distinct,
    smaller assembly step from `core.memory.context_builder.ContextBuilder`
    (which operates on the memory layer's own `MemoryRecord` shape) — not a
    duplicate, the identical "different shape, different home" reasoning
    ADR-0010 already used to keep `ConversationMemory` distinct from
    `CaseMemory`.
  - `prompt_builder.py`: `PromptBuilder` — the task's named "Prompt
    Builder"; assembles fixed system instructions (explicitly instructing
    groundedness, never inventing a fact, and citing sources) + ranked
    context + rendered history + question into a `PromptPayload`, appending
    a visible warning when the question was flagged by prompt-injection
    screening (which happens at the service boundary, not in this
    `core/security`-free package).
  - `llm_provider.py`: `ChatModelProvider` — blueprint §5's "pluggable
    `ModelProvider` interface," first concretely defined this session (a
    `Protocol`: `generate(prompt) -> ChatCompletion`), plus
    `TemplateChatModelProvider` — a genuinely deterministic, non-generative
    default implementation that composes an answer directly from the
    ranked, already-retrieved evidence context, never a network call. Per
    explicit task instruction, no OpenAI/Gemini/Ollama client is
    implemented this session — this is the structural guarantee behind
    "never hallucinate unavailable data": the only content substrate the
    default provider can draw on is verified, retrieved case data.
  - `response_orchestrator.py`: `ResponseOrchestrator` — the task's named
    "Response Orchestrator"; calls the injected `ChatModelProvider`,
    attaches citations via `CitationEngine`, and computes a deterministic
    confidence score (zero evidence -> zero confidence; otherwise scales
    with how much of the ranked context window was filled).
  - `citation_engine.py`: `CitationEngine` — the task's named "Citation
    Engine"; attaches a `SourceReference` to every claimed source id a
    `ChatCompletion` actually names, and silently drops (never fabricates a
    citation for) any claimed source id that doesn't correspond to a real,
    retrieved item — the "output validation" defense constitution §10
    requires for anything an LLM-shaped component emits.
  - `session_manager.py`: `SessionManager` — the task's named "Session
    Manager"; process-local chat-session metadata tracking (id, case_id,
    timestamps, turn count), mirroring `InMemoryConversationMemory`'s
    identical "single-analyst, single-process deployment" scope (ADR-0010).
    Distinct from turn *content* storage (that stays `ConversationMemory`'s
    job).
  - `conversation_manager.py`: `ConversationManager` — the task's named
    "Conversation Manager"; the pipeline orchestrator sequencing tool
    selection -> retrieval -> context assembly -> prompt building, then
    delegating to `ResponseOrchestrator` for the final generate/cite/score
    step. Emits a full `Conversation Audit Log` trail via `audit.py` at
    every stage.
  - `audit.py`/`metrics.py`: the task's named "Conversation Audit Log" (a
    typed `ConversationAuditEvent` + structured `structlog` emission, no new
    DB table — see below) and observability, mirroring every other leaf
    package's established `audit.py`/`metrics.py` shape exactly.
- **`core/services/conversation_service.py`** (new) — `ask_question()`, the
  on-demand entry point: looks up the case (raises `NotFoundError` if
  missing), rejects an empty question (`EmptyQuestionError`), screens the
  question through `core.security.prompt_guard.scan_text` (a chat message is
  exactly the untrusted, potentially attacker-adjacent text constitution
  §10 requires this for), hydrates a `ConversationRetrievalContext` from
  `FindingRepository`/`IOCRepository`/`ReportRepository`/
  `TimelineEventRepository` (reading `Finding.finding_data_json` directly,
  the identical "read the JSON blob, never import `core.findings.models`"
  pattern `case_service._hydrate_mitre_mapping_records` already
  established), reads/writes conversation history via
  `core.memory.conversation_memory.InMemoryConversationMemory`, and calls
  `ConversationManager.answer()`. A new, documented dependency-rules.md
  exception (**rule 4j**) permits this one service module to import
  `core/conversation`, `core.memory.conversation_memory`, and
  `core.security.prompt_guard` directly — worded identically to the
  established 4a-4i family. Never triggers a new investigation run, never
  re-scores a finding, never persists a new record — read-only over what
  the Case Investigation pipeline already produced.
- **No new persisted tables** — blueprint §8's DB design does not name a
  conversation/chat-message table (unlike `IncidentResponsePlan`/`Report`,
  which ADR-0023/0024 confirmed blueprint literally names), and ADR-0010
  already made this exact call deliberately for turn storage ("a persisted
  implementation is a drop-in swap behind the same Protocol later"). This
  session does not revisit that scope: conversation turns stay in
  `InMemoryConversationMemory`; the Conversation Audit Log is structured
  log output, not a new table.
- **New API route** — `POST /api/v1/cases/{case_id}/conversation`
  (`apps/api/routers/conversation.py`, wired into `apps/api/routers/v1.py`),
  the one sanctioned action-trigger `POST` (constitution §6), identical in
  kind to `POST /cases/{case_id}/evidence`. New `apps/api/schemas.py`
  additions: `ConversationAskRequest`/`ConversationAskResponse`/
  `SourceReferenceResponse`. No streaming, no new authentication (existing
  `get_current_user` placeholder, unchanged) — explicit task scope.
- **Testing** — 51 new tests: eleven `core/conversation` unit-test modules
  (models, retrieval — including an oversized-category guard and a
  malformed-entry defense test via `model_construct` to bypass
  `ConversationRetrievalContext`'s own strict validation, mirroring
  ADR-0024's identical precedent — tool_selection, context_builder,
  prompt_builder — including prompt-injection-warning presence/absence,
  llm_provider — including a determinism test, citation_engine —
  including a "never fabricates a citation" test, response_orchestrator,
  session_manager, conversation_manager — the full pipeline invoked
  directly with hand-built input, including a degraded-empty-case test, a
  grounded-with-citations test, a "never fabricates when question is
  unrelated to case data" test, a prompt-injection-flag-carried-through
  test, and a determinism test, audit, metrics), a new
  `tests/integration/test_conversation_service.py` (not-found case, empty
  question, degraded-empty-case, and a full real-pipeline test — SSH-auth-
  log evidence uploaded, then a grounded, cited answer, then a follow-up
  question in the same session), and a new `tests/integration/
  test_api_conversation_routes.py` (404 for missing case, 422 for empty
  question, degraded answer for a case with no evidence, grounded answer
  with citations plus a same-session follow-up, and a prompt-injection-flag
  test via the real API). Full pytest suite (1704 tests, up from 1653),
  `ruff check`/`format --check`, and `scripts/check_dependency_rules.py`
  all pass. New/changed files are individually `mypy --strict` clean (the
  pre-existing, unrelated numpy/pandas whole-repo `mypy` failure — see
  Known Issues — is unchanged, not caused by this session; confirmed by
  reproducing the identical failure on the already-shipped, unmodified
  `apps/api/routers/evidence.py`).

**Explicitly NOT built this session, per the task's own instruction:** the
`apps/web` chat UI page (`6_AI_Analyst_Chat.py`); streaming responses; any
new authentication; a real OpenAI/Gemini/Ollama `ChatModelProvider`
implementation (interface only, as explicitly instructed); persisted
conversation history/audit rows (ADR-0010's existing, deliberate scope,
not reopened); semantic/embedding-based retrieval (keyword-overlap only);
any redesign of `core/memory`, `core/graph`, `core/agents`, or any prior
specialist agent/framework — this feature is purely additive, on-demand,
and read-only over what those already produce.

---

### M5's Report Generator Agent (prior session, unchanged)

This session implemented blueprint §7's **Report Generator Agent**
(`docs/adr/0024-report-generator-agent.md`), **closing M5 entirely** — the
Incident Response half (prior session) plus this session's Report Generator
half together complete the milestone. This is the **tenth** concrete
specialist agent (after `SocAnalystAgent` M1, `PhishingAgent` M2,
`VulnerabilityAssessmentAgent`/`ThreatHunterAgent`/`LinuxSecurityAgent`/
`WebSecurityAgent`/`OwaspSecurityAgent` M4, `MitreMappingAgent` M2,
`IncidentResponseAgent` M5).

**Before writing any code**, this session surfaced a real architecture
question and put it to the user rather than deciding unilaterally
(constitution §14.10): a downstream, cross-cutting "assemble everything into
a report" agent could either (a) run on-demand via a new
`core/services/report_service.py` + `/api/v1/cases/{case_id}/reports` route,
reading Case/Evidence/Finding/Vulnerability/LinuxSecurityFindingRow/
IncidentResponsePlanRow directly from repositories, whole-case-wide — the
option that maps most cleanly onto the task brief's own
"Case -> Load Persisted Data -> ..." pipeline — or (b) a graph node wired
exactly like `MitreMappingAgent`/`IncidentResponseAgent`, cross-cutting,
regenerating on every evidence upload, reading only pre-hydrated
`CaseInvestigationState` fields (the same superstep-isolation constraint
ADR-0023 already worked around). Presented via `AskUserQuestion` with (a)
recommended; the user explicitly chose (b), to keep this agent's
integration identical to the nine that came before it. `docs/adr/
0024-report-generator-agent.md` documents this decision and its accepted
trade-offs (the report is always one run behind for the Incident Response
Plan section, and current-upload-only for four subsystems whose findings
are never persisted — the identical, already-disclosed limitation ADR-0023
accepted for `IncidentResponsePlan`, not a new problem this session
introduced).

**What this session actually built:**
- **`core/reporting/`** (existing leaf package, previously README-only —
  blueprint §6 already named this location; this session filled it in for
  the first time) —
  - `models.py`: `ReportType` (the task's eight named report types —
    Executive Summary, Technical Investigation, Incident Response, IOC
    Summary, MITRE ATT&CK, Timeline, Threat Intelligence, Evidence — plus
    the two original placeholder values `module`/`executive` preserved
    byte-for-byte), `ReportFormat` (PDF/HTML/Markdown/JSON — the task's
    named output formats, structurally supported by every `GeneratedReport`
    equally, no exporter built yet), `ReportSectionType` (the task's twelve
    named sections), `ReportSection`, `ReportStatistics`,
    `ReportValidationResult`, `GeneratedReport` (with a `.section(type)`
    lookup helper).
  - `exceptions.py`: narrow hierarchy (`ReportGenerationError`,
    `UnknownReportTypeError`, `OversizedReportInputError`).
  - `inputs.py`: `ReportGenerationContext` — the one normalized shape every
    upstream subsystem's already-computed signal is reduced to before this
    package ever sees it, mirroring
    `core.incident_response.inputs.IncidentInputFinding`'s role.
  - `section_registry.py`: `REPORT_TYPE_SECTIONS` — the static table of
    which sections each of the eight report types includes (exhaustive over
    the enum, enforced by a unit test), plus `default_title_for` (a
    deterministic, non-LLM-generated title per type). The Technical
    Investigation Report is the most comprehensive: all twelve sections.
  - `section_builders.py`: one pure function per `ReportSectionType` —
    aggregates already-computed data only (finding severities/risk scores,
    resolved MITRE mappings, IOC types, vulnerability/Linux/OWASP records,
    the persisted Incident Response Plan's recommendations) into each
    section's `content` dict, each with an explicit, per-section `is_empty`
    determination (never a generic "any truthy value" heuristic, which
    mis-flagged a real bug caught by this session's own tests — see Key
    Decisions). Every builder is skip-on-malformed via `isinstance` checks,
    belt-and-suspenders defense given `ReportGenerationContext`'s own
    Pydantic validation already rejects non-dict entries at construction.
  - `completeness_validator.py`: `validate_completeness` — the task's named
    "Validate Completeness" stage; flags missing required sections,
    duplicate section types, and an all-empty report.
  - `statistics_calculator.py`: `calculate_statistics` — the task's named
    "Calculate Statistics" stage; every count derived from the context/
    sections already assembled.
  - `confidence_calculator.py`: `calculate_report_confidence` — a report-level
    confidence rollup (non-empty-section fraction × clean-input fraction ×
    a completeness penalty), mirroring
    `core.incident_response.confidence_calculator.calculate_plan_confidence`'s
    discount-by-malformed-fraction shape.
  - `report_engine.py`: `ReportGenerationEngine` — the task's named pipeline
    orchestrator: generate sections -> assemble -> validate completeness ->
    calculate statistics -> build `GeneratedReport`, with an
    oversized-input guard (`OversizedReportInputError`) and an
    `UnknownReportTypeError` guard, never crashing on an empty/degraded
    input (returns a `degraded=True` report instead). Deterministic
    throughout — no LLM reasoning anywhere in this package (task
    requirement), verified by an explicit reproducibility test
    (`test_reporting_report_engine.py::test_generation_is_deterministic_given_the_same_input`).
  - `metrics.py`/`audit.py`: `ReportGenerationMetricsCollector` + structured
    audit-event emission + timing — mirroring `core/incident_response`'s
    established leaf-package shape exactly.
- **`core/tools/report_tools.py`** (new, blueprint's exact named file) —
  `ReportGenerationTool`. Mirrors `ir_tools.py`'s shape exactly: its `run()`
  is a thin wrapper around
  `core.reporting.report_engine.ReportGenerationEngine`, never a duplicate
  reimplementation. Typed, not dict-shaped input: a new, narrowly-scoped
  dependency-rules.md exception (**rule 5c**) permits this one
  `core/tools/*.py` file — and no other — to import `core/reporting`
  directly, mirroring rule 5b's identical `core/incident_response`
  exception for `ir_tools.py`.
- **`core/agents/report_generator_agent.py`** (new) — `ReportGeneratorAgent`,
  the tenth concrete specialist agent, capability `report_generation`.
  Deliberately thin: normalizes `incident_response_finding_records`/
  `mitre_mapping_records` (case-wide), `extracted_indicators`/`evidence`/
  `thoughts` (this run), the current upload's already-hydrated
  `vulnerability_records`/`linux_security_records`/`linux_advisory_records`/
  `owasp_web_records`/`owasp_security_records`, and the case's most recently
  *persisted* `incident_response_plan_record` (new field, see below) into a
  `ReportGenerationContext` (skip-on-malformed via `_dict_records`, never
  crashing) and calls `ReportGenerationTool`, always requesting
  `ReportType.TECHNICAL_INVESTIGATION` (the most comprehensive type).
  Returns a `DEGRADED`, `report=None` "insufficient evidence" result — never
  a fabricated report — when no findings/mappings/IOCs are available yet,
  exactly matching `IncidentResponseAgent`'s "unmapped rather than a forced
  guess" precedent. **Needs no new dependency-rules.md exception of its
  own for calling its tool** — it uses the normal `BaseAgent.use_tool`
  mechanism; it does import `core.reporting.inputs.ReportGenerationContext`/
  `core.reporting.models.{GeneratedReport, ReportType}` directly to
  construct its tool's typed input, mirroring
  `IncidentResponseAgent`'s identical, already-shipped precedent of
  importing `core.incident_response.inputs.IncidentInputFinding`/
  `core.incident_response.models.{IncidentResponsePlan, IncidentSeverity}`
  directly for the same reason (documented in dependency-rules.md rule 5c).
- **One new `CaseInvestigationState` field** — `incident_response_plan_record:
  dict[str, object] | None` (`core/graph/state.py`), hydrated by
  `core/services/case_service.py`'s new
  `_hydrate_incident_response_plan_record` (reads
  `IncidentResponsePlanRepository.find_by_case`, `json.loads`'s
  `plan_data_json`, never imports `core.incident_response.models` into
  `case_service.py`) before the graph runs. Single-writer field (like
  `execution_plan`), deliberately **one run behind** this run's own
  `IncidentResponseAgent` output (docs/adr/0024, Decision 2) — a disclosed,
  accepted limitation mirroring ADR-0023's own precedent, not hidden.
- **Real DB persistence — extends the placeholder `Report` table for the
  first time.** Blueprint §8 literally names `Case ├─ ... └─ 1 Report
  (nullable)`; `core/db/models/report.py`'s `Report`/`ReportType` (created
  two sessions ago, explicitly documented as "no report is ever generated
  yet... until the Report Generator Agent, M5") is this session's intended
  completion point, not a redesign. `ReportType` moved to become the
  canonical definition in `core.reporting.models.ReportType` (the leaf
  package that owns the domain concept), imported by `core/db/models/
  report.py` for column typing — the same "DB imports a sibling leaf's
  model" precedent `core/db/models/finding.py`/`incident_response_plan.py`
  already set. `Report` gained four new, non-nullable columns (`title`,
  `report_data_json`, `overall_confidence`, `degraded`) populated at insert
  time; `ix_reports_case_id` became a unique index (blueprint's literal "1
  nullable" cardinality). Three new, purely additive Alembic migrations
  (`c4d8e1a6f7b3` extends `report_type_enum` with six new values;
  `d5e9f2b7a8c4` adds the four new columns + the unique index;
  `e6f0a3c8b9d5` extends `timeline_event_type_enum` with the new
  `TimelineEventType.REPORT_GENERATED`). `core/db/report_repository.py`'s
  `ReportRepository` gained `find_by_case`/`upsert_for_case` (replaces the
  existing row, never appends a second one for the same case, matching
  `IncidentResponsePlanRepository`'s identical cardinality); takes the
  report as a plain `dict[str, object]`, so `core/services/case_service.py`
  never needs its own new import edge onto `core/reporting` — that Pydantic
  model stays imported only inside `core/db`.
- **Cross-cutting routing, not evidence-type-gated** — mirroring
  `MitreMappingAgent`/`IncidentResponseAgent`'s identical routing exactly:
  `report_generation` is appended to *every* evidence type's
  required-capability list in `core/services/case_service.py`'s
  `_required_capabilities_for`.
- **`core/services/case_service.py`** (modified) — new
  `_hydrate_incident_response_plan_record` (see above); new `_persist_report`
  reads the agent's plain-dict report output and calls the repository,
  records `TimelineEventType.REPORT_GENERATED`, and returns `(report_id,
  report_type, section_count, confidence)` for `(None, None, None, None)` on
  the documented "no report yet" outcome (never zeros — the same
  "insufficient evidence" vs. "no findings" distinction
  `_persist_incident_response_plan` already established). `_run_specialist_agents`
  registers the tenth agent; `CaseInvestigationResult` gained
  `report_id`/`report_type`/`report_section_count`/`report_confidence`.
  `EvidenceUploadResponse` (`apps/api/schemas.py`/`routers/evidence.py`)
  passes them through.
- **`core/graph/{state,investigation_graph}.py`** (modified) —
  `CaseInvestigationState` gained `incident_response_plan_record` (see
  above). `ReportGeneratorAgent` registered/wired as the graph's tenth node
  with the same two-line pattern every prior specialist established.
- **Testing** — 49 new tests: nine `core/reporting` unit-test modules
  (models, section_registry, section_builders — every builder including a
  malformed-entry defense test using `model_construct` to bypass
  `ReportGenerationContext`'s own strict validation, completeness_validator,
  statistics_calculator, confidence_calculator, report_engine — including a
  determinism test and an oversized-input-guard test, metrics),
  `test_tools_report_tools.py`, `test_agents_report_generator_agent.py`
  (empty-state degraded outcome, synthesis from persisted-finding records,
  synthesis from MITRE mappings only, malformed-record skip-don't-crash,
  the persisted Incident Response Plan feeding the Incident Response
  Actions section), and `test_db_report_repository.py` (upsert-creates,
  upsert-replaces-not-appends, find-by-case). Plus two extended assertions
  in the existing end-to-end `test_case_service_pipeline.py` SSH-auth-log
  test (asserting `report_id`/`report_type`/`report_section_count`/
  `report_confidence` and the new timeline event type), a new
  `test_second_upload_replaces_report_not_appends` test proving the "1 per
  case" cardinality end-to-end, and the `test_investigation_graph.py`
  node-set assertion extended to the tenth agent. Full pytest suite (1653
  tests, up from 1604), `ruff check`/`format --check`, and
  `scripts/check_dependency_rules.py` all pass. New/changed files are
  individually `mypy --strict` clean (the pre-existing, unrelated numpy/
  pandas whole-repo `mypy` failure — see Known Issues — is unchanged, not
  caused by this session).

**Explicitly NOT built this session, per the task's own instruction**
("implement only the backend models and generation pipeline... do not build
exporters yet"): `core/reporting/templates/*.html.j2` (Jinja2 templates),
`core/reporting/charts.py` (Plotly figure builders), `core/reporting/
pdf_builder.py` (Jinja2 → ReportLab); an on-demand
`/api/v1/cases/{case_id}/reports` API route to request one of the other
seven report types directly (today only the Technical Investigation Report
auto-regenerates on every evidence upload, cross-cutting); golden-file
snapshot tests (`tests/golden/`, still empty — no concrete renderer exists
yet to snapshot); any closing of the pre-existing "Vulnerability/Linux/
OWASP/Web findings aren't persisted to the `findings` table" gap (unchanged
scope boundary, ADR-0023's Decision 1, inherited as-is by this session's
Findings/Risk Assessment sections); any redesign of
`core/graph/workflow_engine.py`, `core/graph/routing.py`,
`core/agents/planning_agent.py`, `core/agents/coordinator.py`, or any prior
specialist agent/framework.

---

### M5's Incident Response Agent (prior session, unchanged)

Prior session implemented blueprint §7's **Incident Response Agent**
(`docs/adr/0023-incident-response-agent.md`), half-closing M5 at the time —
this session's Report Generator Agent (above) completed the other half,
**closing M5 entirely**. This is the **ninth** concrete specialist agent (after
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
  api/            schemas.py (MODIFIED: +ConversationAskRequest/
                   ConversationAskResponse/SourceReferenceResponse) +
                   routers/{system,cases,evidence,iocs,findings,
                   conversation(NEW),v1(MODIFIED: +conversation router)}.py [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (unchanged this session — no new config
                   knobs needed, mirroring core/reporting's/
                   core/incident_response's identical "no dedicated
                   settings section" precedent)                          [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         (unchanged this session — this feature is a service,
                   not a graph node; still 10 concrete specialist agents) [implemented — 10 concrete specialist agents]
  tools/          (unchanged this session — 10 concrete tools)           [implemented — 10 concrete tools]
  memory/         (unchanged this session — conversation_memory.py/
                   context_builder.py reused as-is, per ADR-0025's
                   "never duplicate" decision)                            [implemented — framework only]
  knowledge/      mitre/, cvss_calculator.py (unchanged)                  [implemented]
  graph/          (unchanged this session — this feature never touches
                   the LangGraph investigation graph)                     [implemented]
  db/             (unchanged this session — no new tables; conversation
                   turns stay in-memory per ADR-0010's existing scope)   [implemented — 12 real domain tables + 5 reference tables]
  parsers/        (unchanged this session)                               [implemented — 17 concrete parsers]
  incident_response/ (unchanged this session)                            [implemented]
  reporting/      (unchanged this session)                               [implemented — pipeline only, no exporters]
  conversation/   (NEW — this session's leaf package: models.py,
                   exceptions.py, retrieval.py, tool_selection.py,
                   context_builder.py, prompt_builder.py, llm_provider.py,
                   response_orchestrator.py, citation_engine.py,
                   session_manager.py, conversation_manager.py, audit.py,
                   metrics.py; deliberately `core/memory`-free — see
                   docs/adr/0025 Decision 1)                              [implemented — pipeline + default template provider, no real LLM client]
  owasp_security/ (unchanged)                                             [implemented]
  owasp_web/      (unchanged)                                             [implemented]
  linux_advisor/  (unchanged — ADR-0019's separate framework)             [implemented]
  linux_security/  (unchanged — ADR-0018's separate framework)            [implemented]
  vulnerabilities/  (unchanged)                                           [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged — this session's service never touches
                   this package directly)                                [implemented]
  security/       prompt_guard.py (unchanged — reused, not modified, by
                   conversation_service.py); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  services/       conversation_service.py (NEW — ask_question(),
                   docs/dependency-rules.md rule 4j) + case_service.py/
                   finding_service.py/evidence_service.py/
                   threat_intel_service.py/vulnerability_service.py/
                   linux_security_service.py/linux_advisor_service.py/
                   web_security_service.py/owasp_security_service.py
                   (unchanged this session)                               [implemented]
data/             (unchanged this session)
scripts/          (unchanged)
tests/
  unit/           235 test modules (+12 this session:
                   test_conversation_{models,retrieval,tool_selection,
                   context_builder,prompt_builder,llm_provider,
                   citation_engine,response_orchestrator,session_manager,
                   conversation_manager,audit,metrics}.py)
  integration:    18 test modules (+2 this session:
                   test_conversation_service.py, test_api_conversation_routes.py)
  golden:         (empty — no concrete report renderer/exporter exists yet)
docs/             19 markdown docs + docs/adr/ (26 ADR files incl.
                   template, +0025) + docs/dependency-rules.md (MODIFIED:
                   +rule 4j, `core/services/conversation_service.py`'s
                   `core/conversation`/`core/memory`/`core/security`
                   exception) + docs/architecture.md (MODIFIED: +core/
                   conversation layer) + docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

1704 tests passing as of this session (1653 prior -> 1704 now: 51 new).
Modified this session: `apps/api/{schemas,routers/v1}.py`,
`docs/{roadmap,dependency-rules,architecture}.md`,
`core/services/README.md`, `CHANGELOG.md`, and this file. New:
`docs/adr/0025-ai-investigation-assistant-conversational-interface.md`,
`core/conversation/{__init__,models,exceptions,retrieval,tool_selection,
context_builder,prompt_builder,llm_provider,response_orchestrator,
citation_engine,session_manager,conversation_manager,audit,metrics,
README}.py`, `core/services/conversation_service.py`,
`apps/api/routers/conversation.py`, 14 new test files — all currently
uncommitted until this session's commit (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extended (not reversed) by
ADR-0001 through ADR-0025. **M2, M4, and M5 are all now fully closed; M6
gains its AI Analyst Chat backend, though the milestone's own demo
criterion (ChromaDB, populated knowledge, a real LLM provider, the chat UI)
still is not met.** This session's deliberate decisions, documented in
`docs/adr/0025-ai-investigation-assistant-conversational-interface.md`:

1. **`core/conversation` stays a `core/memory`-free leaf, even though its
   whole purpose is to sit on top of `ConversationMemory`** — every other
   leaf in `docs/dependency-rules.md` rule 5's list is explicitly forbidden
   from importing `core/memory`; extending that blanket grant to a new
   package whose entire purpose is memory access would blur, not clarify,
   the boundary. Resolution: memory/DB/security access lives in a new
   on-demand `core/services/conversation_service.py` (rule 4j), never in
   `core/conversation` itself.
2. **No `AskUserQuestion` was needed this session**, unlike ADR-0022's/
   ADR-0024's genuine two-way forks — blueprint §13's own wording ("Free-
   form Q&A" a user types on demand) and the already-established rule-4-
   family precedent left only one reasonable shape: an on-demand service,
   not a graph node (the same alternative ADR-0024 offered but the user
   didn't choose there).
3. **The default `ChatModelProvider` is genuinely non-generative, not a
   stub awaiting replacement** — `TemplateChatModelProvider` composes
   answers directly from retrieved evidence text, never inventing content,
   which is the structural mechanism (not just a policy) behind "never
   hallucinate unavailable data."
4. **`CitationEngine` never fabricates a citation** — a `ChatCompletion`
   naming a source id that wasn't actually retrieved is silently dropped,
   the "output validation" defense constitution §10 requires.
5. **No new persisted tables** — blueprint §8 does not name a conversation/
   chat-message table, and ADR-0010 already made this exact call
   deliberately for turn storage; this session does not reopen that scope.
6. **Prompt-injection guarding happens at the service boundary
   (`core.security.prompt_guard.scan_text`), not inside `core/conversation`**
   — consistent with Decision 1's "stay `core/security`-free" shape; a
   flagged question is still answered (never silently dropped), with the
   flag surfaced in both the audit log and the API response.

---

### M5's Report Generator Agent architecture decisions (prior session, unchanged)

This session's deliberate decisions, documented in
`docs/adr/0024-report-generator-agent.md`:

1. **A real architecture choice was put to the user, not decided
   unilaterally** — an on-demand service+API-route shape (reading
   Case/Evidence/Finding/Vulnerability/LinuxSecurityFindingRow/
   IncidentResponsePlanRow directly from repositories) versus a graph-node
   shape matching `MitreMappingAgent`/`IncidentResponseAgent` exactly. The
   user chose the graph-node shape via `AskUserQuestion`, accepting its
   scope trade-offs (one-run-behind Incident Response Plan data,
   current-upload-only Vulnerability/Linux/OWASP/Web data) as the cost of
   integration consistency with the nine prior agents.
2. **The same execution-semantics constraint ADR-0023 already resolved
   applies identically here** — `ReportGeneratorAgent` reads only
   pre-hydrated `*_records` state fields (`incident_response_finding_records`,
   `mitre_mapping_records`, the current upload's five specialist records),
   plus one new case-wide field (`incident_response_plan_record`, hydrated
   from the case's most recently *persisted* `IncidentResponsePlan`) —
   never sibling `agent_outputs` from the same run.
3. **`core/reporting/` is a leaf package (blueprint §6's already-named,
   previously README-only location); only `core/tools/report_tools.py`
   (not the agent) gets a new dependency-rules.md exception (rule 5c) to
   import it directly** — mirroring rule 5b's `ir_tools.py`/
   `core/incident_response` exception exactly.
4. **Real DB persistence extends the placeholder `Report` table for the
   first time** (four new columns, six new `ReportType` values, one row per
   case, upserted) — blueprint §8 literally names this table, so
   persistence was not this session's discretionary choice to skip, the
   identical reasoning ADR-0023 already applied to `IncidentResponsePlan`.
5. **Cross-cutting capability routing** — `report_generation` is appended
   to every evidence type's required-capability list, mirroring
   `mitre_technique_mapping`/`incident_response_synthesis`'s identical
   precedent.
6. **Only the Technical Investigation Report auto-generates per upload** —
   the engine/tool fully support all eight task-named report types on
   request, but generating all eight on every single upload would be
   wasteful busywork with no consumer yet for seven of them; an on-demand
   API route to request a specific type is deferred, not built.
7. **An honest, disclosed scope limitation, not a hidden one** — this
   agent's Findings/Risk Assessment sections inherit ADR-0023's identical,
   already-disclosed limitation (Vulnerability/Linux/OWASP/Web signal is
   only available for the single evidence upload currently being
   processed); its Incident Response Actions section is always one run
   behind the case's true current plan. Neither is a new problem this
   session introduced.

---

### M5's Incident Response Agent architecture decisions (prior session, unchanged)

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

**New this session (AI Investigation Assistant / Conversational Interface, ADR-0025):**

- **Checked for existing infrastructure before writing any code, per
  constitution §14.9** — found `core.memory.conversation_memory.
  ConversationMemory`/`InMemoryConversationMemory` and `core.memory.
  context_builder.ContextBuilder` already built (ADR-0010, two sessions
  prior), specifically anticipating this feature. Reused both directly;
  built no second conversation store or generic ranking algorithm.
- **`core/conversation` is deliberately excluded from `docs/dependency-
  rules.md` rule 5's leaf list** rather than being added to it — that list
  explicitly forbids every member from importing `core/memory`, and this
  package's whole purpose is memory access. A new, narrower exception
  (rule 4j) on `core/services/conversation_service.py` keeps the existing
  boundary's meaning intact instead of diluting it for one new package.
- **The default `ChatModelProvider` (`TemplateChatModelProvider`) is not a
  placeholder that "happens to" avoid hallucination — it structurally
  cannot hallucinate**, since it only ever composes an answer from text
  already present in the retrieved, verified evidence context. This is the
  actual mechanism behind "never hallucinate unavailable data," not just a
  documented promise.
- **`CitationEngine.cite` silently drops any claimed source id that wasn't
  actually retrieved** rather than trusting a `ChatCompletion`'s
  self-reported `used_source_ids` — the same "never trust freeform/
  self-reported LLM output structure" discipline constitution §10 requires,
  applied here even though the default provider is deterministic (a future
  real LLM provider could return anything).
- **No new persisted tables for conversation turns or the audit log** —
  blueprint §8 doesn't name one, and ADR-0010 already made this exact call
  for turn storage. Revisiting it wasn't this session's call to make
  unilaterally without a new blueprint-level requirement.

---

**New in the prior session (Report Generator Agent, ADR-0024):**

- **A real architecture question was put to the user via `AskUserQuestion`
  before any code was written, not decided unilaterally** — recommended the
  on-demand service+API-route shape (it maps far more cleanly onto the task
  brief's own "Case -> Load Persisted Data -> ..." pipeline and onto the
  subsystems whose findings genuinely are persisted case-wide) but the user
  explicitly chose the graph-node shape matching `MitreMappingAgent`/
  `IncidentResponseAgent` exactly, for integration consistency with the nine
  prior agents. Documented as an explicit user choice in ADR-0024, not a
  unilateral engineering call either way.
- **A generic "any truthy content value means non-empty" heuristic for
  `ReportSection.is_empty` was wrong and caught by this session's own unit
  tests before being shipped** — a section whose only populated field is a
  non-empty default string (e.g. `"case_id": "c1"`, `"highest_severity":
  "info"`) was flagging as non-empty even with zero real findings/evidence/
  IOCs behind it. Fixed by making every `section_builders.py` function pass
  its own explicit, count-based `is_empty` determination (e.g. `finding_count
  == 0`) rather than relying on a generic content-dict heuristic — the same
  class of "caught by testing, not by design review" bug ADR-0021 recorded
  for its own log-injection sanitizer.
- **`ReportGenerationContext`'s own strict Pydantic typing (`tuple[dict[str,
  object], ...]`) means section builders can never actually receive a
  non-dict entry in normal operation** — malformed entries are filtered one
  layer up, by the agent's `_dict_records` helper, before the context is
  ever constructed. The section builders' own `isinstance` guards are
  genuine belt-and-suspenders defense (constitution §1.7), not the primary
  enforcement point; testing this defense directly required
  `ReportGenerationContext.model_construct(...)` to deliberately bypass
  validation, a real and correct testing technique for exercising code that
  is structurally unreachable through normal construction.
- **The Technical Investigation Report (the type auto-generated on every
  upload) includes the Incident Response Actions section** — initially
  scoped only to the dedicated `INCIDENT_RESPONSE` report type, but since
  this is meant to be the single comprehensive, always-current report a case
  gets, omitting Incident Response Actions from it would silently under-serve
  the "assemble everything into one structured report" brief. Added to
  `_TECHNICAL_INVESTIGATION_SECTIONS` alongside every other section type.
- **`core/services/case_service.py` needed zero new import edges onto
  `core/reporting`** — `ReportRepository.upsert_for_case` takes the report as
  a plain `dict[str, object]` (not the typed Pydantic model), the identical
  pattern `IncidentResponsePlanRepository.upsert_for_case` already
  established; the Pydantic model stays imported only inside `core/db`.
- **`ReportType`'s canonical home moved from `core/db/models/report.py` to
  `core.reporting.models`** — the enum was originally defined directly on
  the DB model (a schema-only placeholder with no owning leaf package yet);
  now that `core/reporting` exists as a real leaf package, the enum belongs
  to the domain layer that owns the concept, and `core/db` imports it for
  column typing — the same precedent `core/db/models/finding.py`
  (`FindingSeverity`) and `incident_response_plan.py` (`IncidentSeverity`)
  already set. The two original values (`module`, `executive`) were
  preserved byte-for-byte; six new values were added additively.

---

**New in the prior session (Incident Response Agent, ADR-0023):**

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

*(M0–M4/ADR-0015–0024 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session (AI Investigation Assistant, ADR-0025):**

`core.conversation.models.{EvidenceCategory, ConversationRetrievalContext,
SourceReference, RetrievedItem, ToolSelection, AssembledConversationContext,
ConversationHistoryTurn, PromptPayload, ChatCompletion, ConversationAnswer,
ConversationSession, AuditEventAction, ConversationAuditEvent}` (new).

`core.conversation.exceptions.{ConversationError, EmptyQuestionError,
OversizedConversationInputError}` (new).

`core.conversation.retrieval.{RetrievalLayer, MAX_RECORDS_PER_CATEGORY}` (new).

`core.conversation.tool_selection.ToolSelectionEngine` (new).

`core.conversation.context_builder.{ConversationContextBuilder,
DEFAULT_MAX_CHARS}` (new).

`core.conversation.prompt_builder.{PromptBuilder, SYSTEM_INSTRUCTIONS}` (new).

`core.conversation.llm_provider.{ChatModelProvider, TemplateChatModelProvider}`
(new — blueprint §5's provider interface, first defined here).

`core.conversation.response_orchestrator.{ResponseOrchestrator,
OrchestratedResponse}` (new).

`core.conversation.citation_engine.CitationEngine` (new).

`core.conversation.session_manager.{SessionManager, MAX_TRACKED_SESSIONS}` (new).

`core.conversation.conversation_manager.ConversationManager` (new).

`core.conversation.audit.{log_conversation_audit_event, timed_execution}` (new).

`core.conversation.metrics.{ConversationMetricsCollector,
ConversationMetricsSnapshot}` (new).

`core.services.conversation_service.{ask_question, ConversationAskResult,
default_conversation_memory, default_session_manager}` (new).

`apps.api.schemas.{ConversationAskRequest, ConversationAskResponse,
SourceReferenceResponse}` (new).

`POST /api/v1/cases/{case_id}/conversation` (new route).

**New/changed in the prior session (Report Generator Agent, ADR-0024):**

`core.reporting.models.{ReportType, ReportFormat, ALL_REPORT_FORMATS,
ReportSectionType, ReportSection, ReportStatistics, ReportValidationResult,
GeneratedReport}` (new).

`core.reporting.exceptions.{ReportGenerationError, UnknownReportTypeError,
OversizedReportInputError}` (new).

`core.reporting.inputs.ReportGenerationContext` (new).

`core.reporting.section_registry.{REPORT_TYPE_SECTIONS, default_title_for}`
(new).

`core.reporting.section_builders.{build_executive_summary,
build_case_overview, build_investigation_timeline, build_evidence_summary,
build_ioc_summary, build_threat_intelligence_summary, build_mitre_mapping,
build_findings, build_incident_response_actions, build_risk_assessment,
build_recommendations, build_appendix, SECTION_BUILDERS}` (new).

`core.reporting.completeness_validator.validate_completeness` (new).

`core.reporting.statistics_calculator.calculate_statistics` (new).

`core.reporting.confidence_calculator.calculate_report_confidence` (new).

`core.reporting.report_engine.{ReportGenerationEngine,
DEFAULT_MAX_RECORDS_PER_REPORT}` (new).

`core.reporting.metrics.{ReportGenerationMetricsCollector,
ReportGenerationMetricsSnapshot}` (new).

`core.reporting.audit.{AuditAction, log_report_generation_audit_event,
timed_execution}` (new).

`core.tools.report_tools.{ReportGenerationTool, ReportGenerationInput,
ReportGenerationOutput, DEFAULT_MAX_RECORDS_PER_REPORT}` (new).

`core.agents.report_generator_agent.{ReportGeneratorAgent,
default_report_generator_agent_tool_registry, ReportGeneratorAgentResult}`
(new).

`core.db.models.report.{Report, ReportType}` (`ReportType` now re-exported
from `core.reporting.models`, gained six new values: `technical_investigation`,
`incident_response`, `ioc_summary`, `mitre_attack`, `timeline`,
`threat_intelligence`, `evidence`). `Report` gained `title`,
`report_data_json`, `overall_confidence`, `degraded` columns;
`ix_reports_case_id` is now unique.

`core.db.report_repository.ReportRepository` gained `find_by_case`/
`upsert_for_case`.

`core.db.models.timeline_event.TimelineEventType.REPORT_GENERATED` (new).

`core.graph.state.CaseInvestigationState.incident_response_plan_record` (new
field). `core.graph.investigation_graph.build_investigation_graph` now also
registers/wires `ReportGeneratorAgent` (node name `report_generator_agent`).

`core.services.case_service`: new `_hydrate_incident_response_plan_record`,
`_persist_report`; `_required_capabilities_for` now appends
`report_generation` to every evidence type; `_run_specialist_agents`
registers a tenth agent. `CaseInvestigationResult` gained
`report_id`/`report_type`/`report_section_count`/`report_confidence`.

`apps.api.schemas.EvidenceUploadResponse` gained
`report_id`/`report_type`/`report_section_count`/`report_confidence` (all
optional, default `None`).

No `core/reporting/{templates,charts.py,pdf_builder.py}` exporters,
`/api/v1/cases/{case_id}/reports` route, LLM reasoning, or
`core.security.{pii_redaction,approval_gate}` implementation exist as public
interfaces yet.

---

**New/changed in the prior session (Incident Response Agent, ADR-0023):**

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
4. **M5 — closed this session.** The Incident Response Agent half was done
   first (`core/incident_response/`, `core/tools/ir_tools.py`,
   `core/agents/incident_response_agent.py`, real DB persistence — ADR-0023);
   the Report Generator Agent half closes it (`core/reporting/`,
   `core/tools/report_tools.py`, `core/agents/report_generator_agent.py`,
   real DB persistence extending `Report` — ADR-0024). **Deliberately not
   built, per this session's task instruction:** the Jinja2/ReportLab/
   Plotly exporters (`core/reporting/{templates,charts.py,pdf_builder.py}`);
   an on-demand `/api/v1/cases/{case_id}/reports` route.
5. **M6 — further progress this session, still not fully closed.** The AI
   Analyst Chat's backend (`core/conversation/`, `core/services/
   conversation_service.py`, `POST /api/v1/cases/{case_id}/conversation` —
   ADR-0025) is built. Remaining: swap `InMemoryVectorStore` for real
   ChromaDB, populate remaining knowledge data (playbooks), a real
   OpenAI/Gemini/Ollama `ChatModelProvider` (interface-only this session,
   per explicit task scope), the real cross-evidence Threat Timeline UI
   feature, MITRE heatmap/AI Analyst Chat `apps/web` UI pages.
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
   `IncidentResponseAgent`'s and `ReportGeneratorAgent`'s cross-upload
   continuity for those four subsystems — see ADR-0023 Decision 1, ADR-0024
   Decision 7); an asset-criticality inventory; an "analyst requests it"
   on-demand incident-response-plan/report regeneration API route (today
   both only regenerate on the next evidence upload); the Jinja2/ReportLab/
   Plotly exporters and golden-file report-snapshot tests (`tests/golden/`,
   still empty).

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
`findings` table; on PostgreSQL, downgrading the `CaseStatus`/
`timeline_event_type`/`report_type_enum` enum-extension migrations is a
no-op; `Case.labels` has no read endpoint; no case-level authorization/
ownership check; the duplicate-case guard is intentionally narrow; CVSS
v4.0 is vector-validation-only; multi-CVE scan findings fold to their first
CVE; no asset-criticality inventory exists.)*

- **Still open — `mypy core --strict` (whole-repo) cannot run to
  completion.** Unchanged from last session:
  `numpy/__init__.pyi:737: error: Type statement is only supported in
  Python 3.12 and greater [syntax]`, a pre-existing environment
  incompatibility (numpy's inline stubs use PEP 695 syntax, pulled in
  transitively via `pandas` — used by CSV parsers — while
  `pyproject.toml`'s `python_version = "3.11"` rejects that syntax), not
  caused by any session's changes. This session additionally verified:
  every file in `core/reporting` (and every other file touched this
  session) passes `mypy --strict` cleanly when checked directly (bypassing
  the numpy-pulling files, e.g. `investigation_graph.py`/`case_service.py`,
  which transitively import pandas-based parsers). Resolving the numpy/
  mypy/Python-version mismatch itself (pin an older numpy, or bump the
  mypy `python_version`) remains environment maintenance outside any single
  feature session's scope.
- **`Report`'s original "still has no consumer" gap is closed** —
  `ReportGeneratorAgent`/`ReportRepository` are now that consumer
  (ADR-0024); the placeholder is no longer schema-only.
- **`ReportGeneratorAgent`'s cross-upload continuity is uneven across
  subsystems, by a pre-existing, disclosed gap this session inherited, not
  introduced** — `VulnerabilityFinding`/`LinuxSecurityFinding`/SAST/
  `WebSecurityAdvice` findings are still not persisted to the `findings`
  table, so this agent's Findings/Risk Assessment sections only ever
  reflect case-wide SOC/Threat-Hunting/Phishing/MITRE-derived signal plus
  Vulnerability/Linux/OWASP/Web signal for the single evidence upload
  currently being processed. Documented in ADR-0023 Decision 1/ADR-0024
  Decision 7, not hidden.
- **`ReportGeneratorAgent`'s Incident Response Actions section is always
  one investigation run behind the case's true current `IncidentResponsePlan`**
  — `incident_response_plan_record` is hydrated *before* the graph runs,
  while this run's own `IncidentResponseAgent` output is persisted only
  *after* the graph completes (ADR-0024 Decision 2). Not a bug — an
  accepted, documented consequence of the graph-node execution model the
  user explicitly chose.
- **`ReportRepository.upsert_for_case` replaces the entire row on every
  regeneration** — a case with a long investigation history only ever has
  its *latest* Technical Investigation Report queryable; no historical
  report versions are retained (matches blueprint §8's literal "1
  nullable" cardinality, not a bug — the identical precedent
  `IncidentResponsePlanRepository.upsert_for_case` already established).
- **No exporter exists for any of the four `ReportFormat` values yet**
  (PDF/HTML/Markdown/JSON) — `file_path` on the `reports` table stays
  `NULL` in every case; `GeneratedReport` is structurally ready for a
  future `core/reporting/{templates,charts.py,pdf_builder.py}` session to
  consume without any redesign, per this session's explicit task
  instruction to build only the pipeline, not the exporters.
- **No "analyst requests it" on-demand report-regeneration API route
  exists yet, for any of the seven non-auto-generated report types** — the
  Technical Investigation Report currently only regenerates as a side
  effect of the next evidence upload (cross-cutting routing); Executive
  Summary/Incident Response/IOC Summary/MITRE ATT&CK/Timeline/Threat
  Intelligence/Evidence reports are fully supported by
  `ReportGenerationEngine`/`ReportGenerationTool` but have no caller that
  requests them yet.
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
`core/reporting/`, `core/tools/report_tools.py`, and
`core/agents/report_generator_agent.py` are pure Python plus Pydantic; the
three new Alembic migrations use only SQLAlchemy already in use. `jinja2`/
`reportlab`/`plotly`/`pandas` were already present in `requirements.txt`
(unused by this session — reserved for a future exporter session).

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work through the Report Generator Agent (ADR-0024)
commit is committed.

This session's AI Investigation Assistant work added/modified (all to be
committed in this session's single commit — see the commit hash in this
session's final report):

- New: `docs/adr/0025-ai-investigation-assistant-conversational-interface.md`,
  `core/conversation/{__init__,models,exceptions,retrieval,tool_selection,
  context_builder,prompt_builder,llm_provider,response_orchestrator,
  citation_engine,session_manager,conversation_manager,audit,metrics,
  README}.py`, `core/services/conversation_service.py`,
  `apps/api/routers/conversation.py`,
  `tests/unit/{test_conversation_models,test_conversation_retrieval,
  test_conversation_tool_selection,test_conversation_context_builder,
  test_conversation_prompt_builder,test_conversation_llm_provider,
  test_conversation_citation_engine,test_conversation_response_orchestrator,
  test_conversation_session_manager,test_conversation_manager,
  test_conversation_audit,test_conversation_metrics}.py`,
  `tests/integration/{test_conversation_service,
  test_api_conversation_routes}.py`.
- Modified: `apps/api/{schemas,routers/v1}.py`,
  `docs/{roadmap,dependency-rules,architecture}.md`,
  `core/services/README.md`, `CHANGELOG.md`, this file.

Full suite (1704 tests), `ruff check`/`format --check`, and
`scripts/check_dependency_rules.py` all pass. `mypy core --strict`
(whole-repo) fails on the same pre-existing, unrelated numpy/environment
issue as prior sessions (see Known Issues); every file this session
touched is individually `mypy --strict` clean.

---

## Next Recommended Prompt

> The AI Investigation Assistant's backend (`core/conversation/`,
> `core/services/conversation_service.py`,
> `POST /api/v1/cases/{case_id}/conversation`, ADR-0025) is built, tested,
> and answering grounded, cited questions from real persisted case data,
> with a deterministic, non-generative default `ChatModelProvider`. The
> natural next steps, in rough priority order: (1) implement a real
> `ChatModelProvider` (OpenAI/Gemini/Ollama, selected via
> `Settings.llm_provider`) behind the existing Protocol — a provider swap,
> not a pipeline rewrite; (2) the `apps/web` AI Analyst Chat UI page
> (`6_AI_Analyst_Chat.py`), calling `core.services.conversation_service.
> ask_question` the same way `apps/api`'s router does; (3) swap
> `InMemoryVectorStore` for real ChromaDB (`core/memory/long_term.py`) and
> populate MITRE/OWASP knowledge data to close out the rest of M6; or (4)
> the two explicitly-deferred report-generation gaps from ADR-0024: the
> Jinja2/ReportLab/Plotly exporters (`core/reporting/{templates,charts.py,
> pdf_builder.py}`) and an on-demand `/api/v1/cases/{case_id}/reports`
> route for the other seven report types. Preserve every existing file and
> architectural decision described in this document — including all ten
> specialist agents, the Case lifecycle subsystem, the Finding & MITRE
> Engine, every M4 specialist framework, the Incident Response Framework,
> the Report Generation Framework, and the AI Conversation Assistant
> (`core/conversation` is deliberately `core/memory`/`core/db`/
> `core/security`-free — all of that access lives in
> `core/services/conversation_service.py` via rule 4j; don't try to make
> `core/conversation` import `core/memory` directly for a future feature
> without first re-reading ADR-0025's Decision 1) — only extend them. If
> implementing a real LLM provider, decide up front (via ADR) how its
> structured tool-calling response maps to `ChatCompletion.used_source_ids`
> so `CitationEngine`'s "never fabricate a citation" guarantee survives the
> swap from a template provider to a real model. Also worth addressing
> eventually (not urgent, environment-only): the pre-existing
> `mypy core --strict` failure caused by a numpy/pandas stub incompatibility
> with the pinned `python_version = "3.11"` (see this file's Known Issues) —
> either pin an older `numpy` compatible with the target Python version, or
> bump the `pyproject.toml` mypy `python_version` if the project's actual
> runtime floor has moved past 3.11.
