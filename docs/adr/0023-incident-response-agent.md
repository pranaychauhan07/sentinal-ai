# ADR-0023: Incident Response Agent (NIST SP 800-61 Synthesis)

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Blueprint §7's Incident Response Agent is the last unbuilt M5 piece named in
`context/current_state.md`'s "Next Recommended Prompt": *"the correct home
for cross-agent recommendation/escalation/remediation synthesis... deliberately
the 'downstream' consumer that ties a whole case together... pulls from every
other agent's output already in case state — never re-parses evidence
itself."* Building it raised a real architecture question that needed
resolving before any code was written (constitution §14.10): **how** does a
downstream, cross-cutting agent actually reach "every other agent's output"
given the graph's real execution semantics?

## Decision

Two decisions, made together.

### 1. Input shape: pre-hydrated `*_records` fields + case-wide persisted `Finding` rows, never sibling `agent_outputs`

`core/graph/workflow_engine.py`'s `_make_node` docstring documents, as an
empirically-verified fact, that sibling nodes fanned out in the same
LangGraph superstep each run against their own private deep copy of the
pre-superstep state — **a node can never see another node's writes from the
same run** (`core/agents/planning_agent.py` also confirms every
`PlannedStep` it emits has `depends_on=()`; `core/graph/routing.py`'s
`route_from_coordinator` only ever fans out to entry steps; there is no
dependency-aware second-wave dispatch implemented anywhere in this
framework). This ruled out the naive design ("IR Agent reads
`state.agent_outputs[other_agent.name]` after they run in the same
invocation") outright — it would silently return empty results for every
case, not a documented degraded outcome, a correctness bug.

The one path that does work, verified against `core/services/case_service.py`
before committing to it: `vulnerability_records`, `linux_security_records`,
`linux_advisory_records`, `owasp_web_records`, `owasp_security_records`, and
`mitre_mapping_records` are all **inputs** `_run_specialist_agents` hydrates
onto `CaseInvestigationState` *before* `engine.run(state)` is ever called —
not outputs written during the run. Every specialist agent that reads one of
these fields today (`VulnerabilityAssessmentAgent`, `ThreatHunterAgent`,
`LinuxSecurityAgent`, `WebSecurityAgent`, `OwaspSecurityAgent`,
`MitreMappingAgent`) is, in this precise sense, already reading "pre-run
state," not a sibling's live output. `IncidentResponseAgent` reads exactly
the same six fields the same way — no new hydration plumbing for those six,
and no dependency on execution order within the run.

SOC Analyst / Threat Hunting / Phishing findings have no equivalent
pre-hydrated `*_records` field (they derive directly from `state.evidence`/
`state.extracted_indicators`), so for those three the only case-wide signal
available is the same one `MitreMappingAgent` already reads: the case's
already-persisted `Finding` rows (`core.services.finding_service.
list_findings_for_case`), which `generate_findings_for_case` populates from
IOCs regardless of which specialist eventually analyzes them. A new
`_hydrate_incident_response_records` (module docstring, `core/services/
case_service.py`) mirrors `_hydrate_mitre_mapping_records` exactly: reads
`json.loads(Finding.finding_data_json)` directly, never a typed
`core.findings.models.FindingRecord` import.

**Honest limitation, carried into `context/current_state.md`'s Known
Issues, not hidden:** `VulnerabilityFinding`/`LinuxSecurityFinding`/
`OwaspFindings`(SAST)/`WebSecurityAdvice` findings are *not* persisted to the
`findings` table (a pre-existing, already-documented gap — see prior
sessions' Known Issues). This ADR does not close that gap (closing it would
mean redesigning five already-complete, independently-shipped frameworks,
directly violating "never redesign completed modules"). The practical
consequence: `IncidentResponsePlan`'s cross-upload, cross-case continuity is
strongest for SOC/Threat-Hunting/Phishing/MITRE-derived signal (persisted)
and only reflects Vulnerability/Linux/OWASP/Web signal for the *single*
evidence upload currently being processed (the pre-hydrated `*_records`
fields for that upload only — they are not case-wide accumulating lists).
Flagged explicitly, not silently narrowed.

### 2. `core/incident_response/` is a new leaf package; `core/tools/ir_tools.py` gets a documented import exception to reach it directly (rule 5b) — not the agent

The actual response-playbook synthesis (severity classification, MITRE
tactic -> response-category rule mapping, prioritization, execution
ordering, confidence calculation) is genuine, non-trivial deterministic
domain logic — not simple aggregation of an already-computed value the way
`owasp_tools.py`/`web_security_tools.py` aggregate already-scored findings.
Constitution §1.3 ("small, focused modules") and the precedent every other
non-trivial domain already set (`core/owasp_security`, `core/linux_advisor`,
`core/vulnerabilities`, `core/linux_security`) both point the same
direction: this logic gets its own leaf package, not one oversized
`core/tools/ir_tools.py` file.

Blueprint's folder structure (§6) names only `core/tools/ir_tools.py` for
Incident Response — but ADR-0019/0020/0021 already established the pattern
of a blueprint-named `core/tools/*.py` file staying a *thin* wrapper while
the real logic lives in a new, purpose-built package the blueprint didn't
originally enumerate. `core/incident_response/` follows that precedent, but
with a twist matching this package's actual role: unlike
`owasp_tools.py`/`web_security_tools.py` (thin aggregators of an
*already-computed* value with no cross-leaf import at all), this package's
real synthesis work has to happen somewhere a tool can call it — the exact
shape `core/tools/mitre_tools.py` already established for
`MitreMappingResolutionTool` wrapping `core.knowledge.mitre.lookup.
MitreLookup` directly. `core/tools/ir_tools.py`'s
`IncidentResponsePlanGenerationTool` is that same shape: a thin `BaseTool`
subclass whose `run()` body is one call into
`core.incident_response.response_plan_engine.ResponsePlanEngine` — blueprint's
literal `ir_tools.py` requirement is satisfied, and the actual synthesis
logic still lives entirely inside `core/incident_response/`, not duplicated
into the tool file.

`core/tools/ir_tools.py` is granted the same kind of exception
`core/tools/mitre_tools.py` already has for `core/knowledge` (rule 5): **may
import `core/incident_response` directly** (new rule 5b,
`docs/dependency-rules.md`). `core/agents/incident_response_agent.py` itself
needs **no** new import exception — like every other specialist agent, it
calls its tool through the normal `BaseAgent.use_tool` mechanism
(constitution §4.5) and only imports `core.tools.ir_tools`'s typed Input/
Output models, mirroring `MitreMappingAgent`'s identical relationship to
`core.tools.mitre_tools` (the agent imports its own tool's typed contracts,
never the leaf package the tool wraps). This keeps "which layer gets the
cross-leaf import exception" answered the same way for both
downstream-synthesizer agents this codebase now has — always the tool
layer, never the agent layer.

`core/incident_response/` never imports `core/agents`, `core/graph`, or
`core/memory` (rule 5's "leaves never call up," unchanged); it imports
nothing from `core/knowledge` either — every reference table it needs (the
ATT&CK-tactic-ID -> `ResponseCategory` mapping) is a small, static lookup
table owned inside the package itself, the same "small enough to live
inside the package" precedent `core/owasp_security`/`core/owasp_web`/
`core/linux_advisor` already established (rule 5).

### 3. Persistence: `IncidentResponsePlan` is a real, blueprint-named table (unlike `SastAdvice`/`WebSecurityAdvice`/`LinuxSecurityAdvice`)

Blueprint §8's DB design literally names `Case ├─ ... └─ 1
IncidentResponsePlan (nullable)` — a one-per-case, nullable relationship,
unlike the ADR-0019/0020/0021 frameworks (which chose "no DB persistence" as
a documented *scope-narrowing* decision because blueprint's DB section never
named them). This is not a discretionary choice this session gets to make
the same way those did: the blueprint's own schema already calls for it, and
the task brief's pipeline explicitly names "Persist Response Plan" as a
stage. `core/db/models/incident_response_plan.py` (new) is a real table,
one row per case (unique `case_id`, upserted — replaced, not appended — on
every regeneration, matching the "1 nullable" cardinality literally), with
its own repository (`core/db/incident_response_plan_repository.py`) and
Alembic migration.

### 4. Cross-cutting, not evidence-type-gated (mirrors ADR-0022 exactly)

`incident_response_synthesis` is appended to *every* evidence type's
required capabilities in `_required_capabilities_for`, identically to
`mitre_technique_mapping` — Finding generation (and therefore MITRE mapping
and now IR synthesis) already runs unconditionally on every upload. Internal
severity gating (not graph-level skip) decides whether the generated plan is
a full multi-phase plan or a `DEGRADED` "insufficient evidence"/"below
response threshold" result — mirroring `MitreMappingAgent`'s
"unmapped rather than a forced guess" pattern exactly. Blueprint §7's
"if severity crosses threshold or analyst requests it" is implemented as:
the plan is *always* generated deterministically from whatever findings
exist (reproducibility requirement, task brief), but a case with zero
qualifying findings returns `DEGRADED` with no manufactured actions, and
`Settings.incident_response_min_severity_for_isolation`-style thresholds
(see `core/incident_response/severity_classifier.py`) gate which
*categories* of action (host isolation, service shutdown) a given severity
actually earns — a LOW-severity finding never escalates to isolation
regardless of how many times the plan regenerates. "Analyst requests it"
on-demand regeneration (an explicit API trigger, independent of the next
evidence upload) is named in Remaining Work, not built this session — it
requires no new architecture, only a new API route calling the same
`core/services/incident_response_service`-shaped entry point this session
already provides via `case_service.py`.

## Alternatives Considered

- **Wire IR Agent with `depends_on` on every other specialist, and teach
  `route_from_coordinator`/`WorkflowEngine` to execute in dependency-ordered
  waves.** Rejected: this is a real framework change to `core/graph`
  (explicitly out of scope — "Do NOT redesign the Coordinator" — and the
  task brief's own instruction not to touch already-shipped orchestration
  infrastructure). `PlannedStep.depends_on`/`parallel_group` already exist
  as unused fields for exactly this future extension; this session does not
  activate them.
- **Have `IncidentResponseAgent` re-read `Vulnerability`/`LinuxSecurityFinding`/
  SAST/Web findings from their own (non-existent) DB tables.** Rejected:
  none of those tables exist (ADR-0019/0020/0021 explicitly chose no
  persistence); creating them is a five-framework redesign, not an
  extension.
- **Make `core/tools/ir_tools.py` the one file holding all synthesis
  logic**, matching blueprint's literal single-file listing. Rejected:
  violates constitution §1.3 ("if a module's responsibility needs 'and' to
  describe it, split") — severity classification *and* rule matching *and*
  prioritization *and* ordering *and* confidence calculation is five
  responsibilities in one file, and every other non-trivial domain in this
  codebase already gets its own package.
- **No DB persistence, matching `core/owasp_security`/`core/linux_advisor`'s
  precedent.** Rejected: blueprint's own §8 DB design names this table
  explicitly (`1 IncidentResponsePlan (nullable)`), and the task brief's
  pipeline explicitly lists "Persist Response Plan" — unlike the three prior
  frameworks, there is no honest reading of the governing documents that
  supports skipping persistence here.

## Consequences

**Easier:** Every future evidence upload's response plan regenerates
deterministically and is queryable per case (`GET` route deferred to a
future API session, not built here); the plan's `ResponseMetrics` give the
future Report Generator Agent (M5's other half, still not built) a ready-made
structured input; the tactic -> category rule table is a single, testable,
documented source of truth for "what does a T1110 finding actually mean the
analyst should do."

**Harder / foreclosed:** A case whose only findings come from a
Vulnerability/Linux/OWASP/Web upload gets a materially thinner IR plan than
one from a SOC/Phishing upload, until a future session closes the
finding-persistence gap for those frameworks (tracked, not silently
absorbed) — this ADR does not pretend otherwise. On-demand ("analyst
requests it") regeneration outside the evidence-upload pipeline is not
available yet; only "runs on every upload, internally gated by severity" is
built this session.

**Never touched:** `core/graph/workflow_engine.py`, `core/graph/routing.py`,
`core/agents/planning_agent.py`, `core/agents/coordinator.py`, and every
prior specialist agent/framework (`SocAnalystAgent` through
`MitreMappingAgent`) — extended (a ninth node, a ninth capability, one more
`*_records`-shaped hydration function) but never redesigned.
