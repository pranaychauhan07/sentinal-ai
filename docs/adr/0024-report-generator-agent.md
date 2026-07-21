# ADR-0024: Report Generator Agent

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Blueprint §7's Report Generator Agent is M5's second and final piece:
*"Assembles all case findings into module-specific and case-level executive
... reports... template selection, chart generation, narrative synthesis...
Tools used: `reporting/` package (deterministic — the PDF is templated, not
LLM-freeform, so reports are reproducible)."* The task brief asks for eight
named report types (Executive Summary, Technical Investigation, Incident
Response, IOC Summary, MITRE ATT&CK, Timeline, Threat Intelligence, Evidence)
assembled deterministically from every already-completed subsystem's
persisted/hydrated output, never re-running analysis.

Building it raised the same class of question ADR-0022/0023 already
resolved for their own agents: **how** does a downstream, cross-cutting
agent reach "every other agent's/subsystem's output" given the graph's real
execution semantics (`core/graph/workflow_engine.py`'s documented
per-superstep state isolation — a node never sees a sibling's writes from
the same run)? Presented to the user as an explicit choice before any code
was written (constitution §14.10): an on-demand service+API-route shape
(reading Case/Evidence/Finding/Vulnerability/LinuxSecurityFindingRow/
IncidentResponsePlanRow directly from repositories, case-wide, triggered by
an analyst action) versus a graph-node shape matching `MitreMappingAgent`/
`IncidentResponseAgent`'s established pattern exactly (cross-cutting,
regenerates on every upload, reads only pre-hydrated state fields). The user
chose the graph-node shape, to keep this agent's integration identical to
the nine that came before it.

## Decision

### 1. `ReportGeneratorAgent` is the tenth concrete specialist agent, wired exactly like `MitreMappingAgent`/`IncidentResponseAgent`

Cross-cutting: `report_generation` is appended to every evidence type's
required capabilities in `_required_capabilities_for` (mirroring
`mitre_technique_mapping`/`incident_response_synthesis` exactly). It regenerates
a comprehensive **Technical Investigation Report** on every evidence upload,
replacing the case's previous report (one row per case, upserted — the same
"1 nullable" cardinality ADR-0023 established for `IncidentResponsePlan`).
Generating the other seven report types is fully supported by the underlying
`core.reporting.report_engine.ReportGenerationEngine`/
`core.tools.report_tools.ReportGenerationTool` (any caller can request any of
the eight `ReportType` values) — but only the Technical Investigation Report
is auto-generated per upload; an "analyst requests a specific report type
on-demand" API route is deferred (Remaining Work), the identical scope
boundary ADR-0023 already accepted for on-demand `IncidentResponsePlan`
regeneration.

### 2. Input shape: the same pre-hydrated `*_records` fields every sibling specialist already reads, plus one new field for the persisted Incident Response Plan

Per ADR-0023's already-established, empirically-verified fact
(`workflow_engine.py::_make_node`'s docstring — sibling nodes fanned out in
the same LangGraph superstep never see each other's writes), this agent
cannot read `state.agent_outputs` from `SocAnalystAgent`/`VulnerabilityAssessmentAgent`/
etc. produced in *this* run. It reads exactly the same case-wide and
current-upload-scoped fields `IncidentResponseAgent` already reads
(`incident_response_finding_records`, `mitre_mapping_records` — case-wide,
persisted `Finding` rows; `vulnerability_records`, `linux_security_records`,
`linux_advisory_records`, `owasp_web_records`, `owasp_security_records` —
current-upload only) plus `state.extracted_indicators` (this upload's IOCs),
`state.evidence` (this upload's normalized evidence, for a count/type
summary), and `state.thoughts`/`state.execution_history` (this run's ReAct
trail, used for the Investigation Timeline section — necessarily scoped to
this run, not the case's full cross-upload timeline, since the persisted
`TimelineEvent` table is a `core/services`-only read this agent has no
sanctioned path to without a new dependency-rules exception nobody asked
for).

One genuinely new case-wide input is needed: the case's already-persisted
`IncidentResponsePlan` (for the Incident Response Actions section) is not
covered by any existing `*_records` field — `IncidentResponseAgent`'s own
plan output lives only in its own run's private state copy, never visible to
a sibling. `core/graph/state.py` gains
`incident_response_plan_record: dict[str, object] | None = None` (a single,
non-concurrent field — mirrors `execution_plan`'s shape, since only
`core/services/case_service.py`'s new `_hydrate_incident_response_plan_record`
writes it, before the graph runs, never a specialist agent), hydrated by
reading `IncidentResponsePlanRepository.find_by_case` and `json.loads`-ing
its `plan_data_json` column — the same "read the persisted JSON blob
directly, never import the leaf package's typed model into `case_service.py`"
pattern `_hydrate_incident_response_records` already established for
`Finding.finding_data_json`.

**Honest, disclosed limitation (mirrors ADR-0023's own precedent exactly):**
this field reflects whichever `IncidentResponsePlan` was persisted by the
*previous* investigation run (hydration happens before `engine.run(state)`,
and `IncidentResponsePlanRepository.upsert_for_case` for *this* run's plan
happens after the graph completes) — one run behind, never the current run's
freshly-generated plan. On a case's very first evidence upload, this field is
`None` and the Incident Response Actions section reports "no plan generated
yet," not a fabricated placeholder.

### 3. `core/reporting/` becomes a real leaf package; `core/tools/report_tools.py` gets a documented import exception (rule 5c) — not the agent

Mirrors ADR-0023's identical shape for `core/incident_response`/
`core/tools/ir_tools.py` exactly, for the identical reason: report assembly
(section generation, completeness validation, statistics rollup, confidence
calculation) is genuine, non-trivial deterministic domain logic — not a
one-line aggregation `owasp_tools.py`-style dict passthrough would fit. It
gets its own package (`core/reporting/`, blueprint §6's already-named
location, previously README-only) rather than being crammed into
`core/tools/report_tools.py`.

`core/tools/report_tools.py` (blueprint's exact named location for the
Report Generator's tool) stays a *thin* `BaseTool` wrapper whose `run()` is
one call into `core.reporting.report_engine.ReportGenerationEngine` — the
same shape `ir_tools.py`/`IncidentResponsePlanGenerationTool` already
established for `core.incident_response.response_plan_engine.ResponsePlanEngine`.
New `docs/dependency-rules.md` rule 5c grants `core/tools/report_tools.py`
(and no other `core/tools/*.py` file) permission to import `core/reporting`
directly — worded identically to rule 5b's `ir_tools.py` grant.
`core/agents/report_generator_agent.py` needs **no** new import exception:
like every other specialist agent, it only imports
`core.tools.report_tools`'s typed Input/Output models and calls through
`BaseAgent.use_tool`.

`core/reporting/` never imports `core/agents`, `core/graph`, or `core/memory`
(leaves never call up). It imports nothing from `core/knowledge` either —
every reference table it needs (which sections belong to which report type)
is a small, static lookup table owned inside the package, the same
"small enough to live inside the package" precedent
`core/owasp_security`/`core/incident_response` already established.

### 4. Persistence: `Report` (blueprint §8's already-scaffolded, placeholder table) is extended additively, never redesigned

`core/db/models/report.py`'s `Report`/`ReportType` (created empty two
sessions ago, explicitly documented as "no report is ever generated yet...
until the Report Generator Agent, Milestone M5") is this session's exact,
intended completion point — not a redesign of a completed module. Two
additive changes:

- `ReportType` (the enum) moves to become the canonical definition in
  `core.reporting.models.ReportType` — the leaf package that owns the
  *domain* concept — and `core/db/models/report.py` imports it for column
  typing, the identical "DB imports a sibling leaf's model" precedent
  `core/db/models/finding.py` (`FindingSeverity`) and
  `core/db/models/incident_response_plan.py` (`IncidentSeverity`) already
  set. Its two existing values (`module`, `executive`) are preserved
  byte-for-byte (`module` stays as an unused legacy value, never removed —
  migrations are additive-only, constitution §7); six new values are added
  (`technical_investigation`, `incident_response`, `ioc_summary`,
  `mitre_attack`, `timeline`, `threat_intelligence`, `evidence`) to cover the
  task's eight named report types (`executive` already covers "Executive
  Summary").
- `Report` gains four new, non-nullable columns populated at insert time in
  the same transaction (so `NOT NULL` needs no server default — the table is
  guaranteed empty in every environment, per its own placeholder docstring):
  `title`, `report_data_json` (the full serialized `GeneratedReport`, the
  same "denormalized columns + one full JSON blob" shape
  `IncidentResponsePlanRow.plan_data_json` already established),
  `overall_confidence`, `degraded`. `file_path`/`generated_at` stay
  nullable — real PDF/HTML/Markdown export (blueprint's `reporting/pdf_builder.py`,
  `charts.py`, Jinja2 templates) is explicitly **not** built this session
  (task instruction: "implement only the backend models and generation
  pipeline... do not build exporters yet"), so `file_path` stays `NULL`
  until a future session adds a real exporter; `generated_at` is populated
  now (a report genuinely is generated, just not yet exported to a file).
  `ReportRepository` gains `find_by_case`/`upsert_for_case`, mirroring
  `IncidentResponsePlanRepository`'s identical shape and "replace, don't
  append" cardinality.

Two new, purely additive Alembic migrations: one extends `report_type_enum`
with the six new values (dialect-branching identically to `27d5a3474dca`/
`b7e4d2f8a1c9`'s established pattern); one adds the four new `reports`
columns.

### 5. Cross-cutting, not evidence-type-gated (mirrors ADR-0022/0023 exactly)

`report_generation` is appended to *every* evidence type's required
capabilities in `_required_capabilities_for` — Finding generation (and
therefore MITRE mapping, incident response synthesis, and now report
generation) already runs unconditionally on every upload.

## Alternatives Considered

- **On-demand service + new `/api/v1/cases/{case_id}/reports` route, reading
  Case/Evidence/Finding/Vulnerability/LinuxSecurityFindingRow/
  IncidentResponsePlanRow directly via repositories, whole-case-wide.**
  Presented to the user as the recommended option (it maps far more cleanly
  onto the task brief's own "Case -> Load Persisted Data -> ..." pipeline and
  onto four of the four subsystems whose findings genuinely are persisted
  case-wide). Rejected by explicit user choice in favor of matching the
  existing graph-node integration pattern exactly, accepting the resulting
  "one run behind" / "current-upload-only for four subsystems" scope
  limitations as the honest trade-off (identical in kind to ADR-0023's own
  disclosed limitation, not a new category of problem).
- **Wire `ReportGeneratorAgent` with `depends_on` on every other specialist
  so it runs in a dependency-ordered second wave, seeing this run's real
  sibling outputs.** Rejected: a real `core/graph`/`workflow_engine.py`
  framework change, explicitly out of scope (never redesign already-shipped
  orchestration infrastructure); `PlannedStep.depends_on`/`parallel_group`
  remain unused fields reserved for a future extension, as ADR-0023 already
  noted.
- **Auto-generate all eight report types on every upload.** Rejected as
  wasteful busywork with no consumer yet for seven of the eight (no export
  route, no UI) — the engine/tool support generating any of the eight on
  request; only the single most comprehensive type (Technical Investigation)
  is auto-persisted per upload, matching `IncidentResponsePlan`'s identical
  "one plan per case, always kept current" precedent.
- **Fold report assembly logic directly into `core/tools/report_tools.py`.**
  Rejected: violates constitution §1.3 exactly as ADR-0023 already argued for
  `core/incident_response` — section generation, validation, statistics, and
  confidence calculation are four distinct responsibilities, not one file's
  worth.

## Consequences

**Easier:** Every evidence upload keeps a case's Technical Investigation
Report current and queryable (`Report` row, one per case); the underlying
engine already supports all eight report types end-to-end for a future
on-demand route or exporter to call directly, with zero further engine
changes.

**Harder / foreclosed:** The Incident Response Actions section is always one
run behind the case's true current plan; the Findings/Risk Assessment
sections are materially thinner for cases whose evidence came only from
Vulnerability/Linux/OWASP/Web uploads (the same four-subsystem
finding-persistence gap ADR-0023 already disclosed, not reintroduced here);
the Investigation Timeline section reflects only the current run's ReAct
trail, not the case's full persisted `TimelineEvent` history; no PDF/HTML/
Markdown file is ever produced yet (`file_path` stays `NULL`) — this is a
deliberate, task-instructed scope boundary, not an oversight; no on-demand
API route to request one of the other seven report types exists yet.

**Never touched:** `core/graph/workflow_engine.py`, `core/graph/routing.py`,
`core/agents/planning_agent.py`, `core/agents/coordinator.py`, and every
prior specialist agent/framework (`SocAnalystAgent` through
`IncidentResponseAgent`) — extended (a tenth node, a tenth capability, one
more `*_records`-shaped hydration field) but never redesigned.
