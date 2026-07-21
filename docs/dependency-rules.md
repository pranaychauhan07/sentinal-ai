# Dependency Rules

Strict, enforced rules for which layers may import from which. Violating
these is a blocking code-review finding and, where mechanically checkable, a
CI failure (`scripts/check_dependency_rules.py`, run via pre-commit and CI).

## The layer stack (import direction flows one way: top → down only)

```
apps/web , apps/api            (frontends — presentation only)
        ↓ may import
core/services                  (orchestration for frontends)
        ↓ may import           ↘ core/conversation, core/memory, core/security
                                  (AI Analyst Chat — conversation_service.py only, rule 4j)
                                ↘ core/reporting
                                  (Report export/rendering — report_export_service.py only, rule 4k)
        ↓ may import
core/graph                     (LangGraph workflow)
        ↓ may import           ↘ core/parsers, core/memory (evidence ingestion only — rule 4a)
core/agents                    (specialist agents)
        ↓ may import           ↘ core/threat_intel, core/parsers (IOC extraction only — rule 4b)
                                ↘ core/findings, core/knowledge (Finding/MITRE mapping only — rule 4c)
                                ↘ (no edge onto core/vulnerabilities — rule 4e is services-only)
                                ↘ (no edge onto core/linux_security — rule 4f is services-only)
                                ↘ (no edge onto core/linux_advisor — rule 4g is services-only)
                                ↘ (no edge onto core/owasp_web — rule 4h is services-only)
                                ↘ (no edge onto core/owasp_security — rule 4i is services-only)
                                ↘ (no edge onto core/incident_response — it is core/tools-only, rule 5b)
                                ↘ (no edge onto core/reporting — it is core/tools-only, rule 5c)
core/tools , core/parsers , core/threat_intel , core/findings , core/vulnerabilities ,
core/linux_security , core/linux_advisor , core/owasp_web , core/owasp_security ,
core/incident_response
        (deterministic functions)
        ↓ may import
core/knowledge , core/memory , core/security , core/db , core/reporting , core/config
        (leaf layers — import each other sparingly and only where documented below)
```

## Rules

1. **`core/` never imports from `apps/`.** No exceptions. This is the rule
   that keeps `core/` framework-agnostic and testable headlessly. Enforced by
   `scripts/check_dependency_rules.py` (static import scan) in CI.

2. **`apps/web` and `apps/api` never import each other.** Both are
   independent front doors to `core/services`; if they need to share logic,
   that logic belongs in `core/services`, not in one importing from the other.

3. **`apps/web` pages/components and `apps/api` routers contain no business
   logic.** They validate/render and call exactly one `core/services`
   function per user action. If you find yourself writing an `if` statement
   that makes a security/business decision inside a Streamlit page or a
   FastAPI router, that logic belongs in `core/services` or below.

4a. **`core/services/evidence_service.py` may import `core/parsers` and
   `core/memory` directly** — the one documented exception to "services only
   call `core/graph`." Evidence ingestion (upload, validate, fingerprint,
   parse, normalize, persist) is deterministic, pre-investigation processing
   with no agent/LLM reasoning involved (blueprint §9 steps 1-3 happen
   *before* the Coordinator/graph); routing it through `core/graph` for no
   reason would be architecture-for-its-own-sake. See
   `docs/adr/0011-evidence-ingestion-pipeline-shape.md`. No other
   `core/services` module gets this exception without its own ADR — this is
   scoped to evidence ingestion specifically, not a general services→parsers
   license.

4b. **`core/services/threat_intel_service.py` may import `core/threat_intel`,
   `core/parsers`, and `core/memory` directly** — the second documented
   exception to "services only call `core/graph`," scoped exactly to this
   module the same way rule 4a is scoped exactly to `evidence_service.py`.
   IOC extraction (discover, validate, normalize, deduplicate, classify,
   score, persist) is deterministic, pre-investigation processing with no
   agent/LLM reasoning involved. See
   `docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`. No
   other `core/services` module gets this exception without its own ADR.

4c. **`core/services/finding_service.py` may import `core/findings`,
   `core/threat_intel` (models only), `core/knowledge`, and `core/memory`
   directly** — the third documented exception to "services only call
   `core/graph`," worded identically to 4a/4b and scoped exactly to this
   module. Finding generation (MITRE mapping, evidence aggregation,
   confidence calculation, deduplication, persistence) is deterministic,
   pre-investigation processing with no agent/LLM reasoning involved. See
   `docs/adr/0013-finding-mitre-intelligence-engine-shape.md`. No other
   `core/services` module gets this exception without its own ADR.

4d. **`core/services/case_service.py` may import `core.agents.{registry,
   soc_analyst_agent, phishing_agent, vulnerability_agent}`,
   `core.memory.{case_memory, repository, long_term, manager}`, and
   `core.parsers.models` directly** — the fourth documented exception to
   "services only call `core/graph`," worded identically to 4a/4b/4c. Every
   other `core/services` call in this module (`evidence_service`,
   `threat_intel_service`, `finding_service`, `vulnerability_service`,
   `core/graph/investigation_graph.py`) goes through the normal sanctioned
   edges; this specific exception exists for two narrow reasons:
   constructing a session-scoped `CaseMemory` and a *fresh* (never the
   process-wide cached `default_agent_registry()`) `AgentRegistry` before
   delegating to `core/graph` (reusing the cached singleton here would
   permanently bake in whichever caller's `case_memory` (or lack of one)
   happened to register `SocAnalystAgent`/`PhishingAgent`/
   `VulnerabilityAssessmentAgent` first — a real correctness hazard, not a
   style preference); and, added by ADR-0027, writing this run's new
   findings/report into long-term memory via `core.memory.manager.
   default_long_term_memory()` after `_persist_report` — blueprint §9 step
   11 ("Memory Agent (write)"), closed here rather than by a new
   `core/agents/memory_agent.py` (see ADR-0027's "Alternatives
   Considered"). The `core.parsers.models` import is for type reuse only
   (`EvidenceType`, `NormalizedEvidence`, `Severity`), the identical
   sideways leaf-model precedent `core/db/models/case.py`/`evidence.py`
   already established. See
   `docs/adr/0014-case-model-and-first-api-routes-shape.md`, extended by
   `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`,
   `docs/adr/0017-vulnerability-assessment-framework.md`, and
   `docs/adr/0027-production-memory-embedding-chat-provider-infrastructure.md`.
   This module also reads `core.db.{ioc_repository, finding_repository}`
   directly — not a new exception, since `core/services` -> `core/db` is
   always sanctioned (constitution §7) and every other repository this
   module needs (`CaseRepository`, `CaseNoteRepository`, ...) is already
   imported the same way. No other `core/services` module gets the
   agents/memory exception without its own ADR.

4e. **`core/services/vulnerability_service.py` may import
   `core/vulnerabilities`, `core/parsers`, and `core/memory` directly** — the
   fifth documented exception to "services only call `core/graph`," worded
   identically to 4b's precedent for `threat_intel_service.py`. Vulnerability
   assessment (extract, validate, normalize, deduplicate, correlate, score,
   generate findings, persist) is deterministic, pre-investigation
   processing with no agent/LLM reasoning involved. See
   `docs/adr/0017-vulnerability-assessment-framework.md`. No other
   `core/services` module gets this exception without its own ADR.

4f. **`core/services/linux_security_service.py` may import
   `core/linux_security`, `core/parsers`, and `core/memory` directly** — the
   sixth documented exception to "services only call `core/graph`," worded
   identically to 4b/4e's precedent. Linux security / threat-hunting
   analysis (evidence normalization, authentication/privilege/persistence
   analysis, behavior detection, scoring, finding generation, persist,
   publish, notify) is deterministic, pre-investigation processing with no
   agent/LLM reasoning involved. See
   `docs/adr/0018-linux-security-threat-hunting-framework.md`. No other
   `core/services` module gets this exception without its own ADR.

4g. **`core/services/linux_advisor_service.py` may import
   `core/linux_advisor` and `core/parsers` directly** — the seventh
   documented exception to "services only call `core/graph`," worded
   identically to 4e/4f's precedent. Linux command/permission advisory
   analysis (command analysis, permission analysis, hardening
   recommendation, risk assessment) is deterministic, pre-investigation
   processing with no agent/LLM reasoning involved. Unlike 4e/4f, this
   module never touches `core/memory` (it has no note-taking behavior — see
   `docs/adr/0019-linux-security-advisor-agent.md` point 3, "no DB
   persistence"). See `docs/adr/0019-linux-security-advisor-agent.md`. No
   other `core/services` module gets this exception without its own ADR.

4h. **`core/services/web_security_service.py` may import `core/owasp_web`
   and `core/parsers` directly** — the eighth documented exception to
   "services only call `core/graph`," worded identically to 4g's precedent.
   OWASP-mapped HTTP traffic analysis (header analysis, cookie analysis,
   JWT analysis, misconfiguration detection, finding generation, risk
   assessment) is deterministic, pre-investigation processing with no
   agent/LLM reasoning involved. Like 4g, this module never touches
   `core/memory` (no note-taking behavior — see
   `docs/adr/0020-owasp-web-security-agent.md` point 3, "no DB
   persistence"). See `docs/adr/0020-owasp-web-security-agent.md`. No other
   `core/services` module gets this exception without its own ADR.

4i. **`core/services/owasp_security_service.py` may import
   `core/owasp_security` and `core/parsers` directly** — the ninth
   documented exception to "services only call `core/graph`," worded
   identically to 4h's precedent. Source-code SAST analysis (language
   detection, AST parsing, rule matching, finding generation, confidence
   calculation, risk assessment) is deterministic, pre-investigation
   processing with no agent/LLM reasoning involved. Like 4g/4h, this module
   never touches `core/memory` (no note-taking behavior — see
   `docs/adr/0021-owasp-security-agent-ast-sast.md` point 3, "no DB
   persistence"). See `docs/adr/0021-owasp-security-agent-ast-sast.md`. No
   other `core/services` module gets this exception without its own ADR.

4j. **`core/services/conversation_service.py` may import `core/conversation`,
   `core.memory.{conversation_memory, long_term, manager}`,
   `core.knowledge.{registry, retrieval, models}`, and
   `core.security.prompt_guard` directly** — the tenth documented exception
   to "services only call `core/graph`," worded identically to 4a-4i's
   established shape. Case-scoped conversational Q&A (retrieval over
   already-persisted Findings/IOCs/MITRE mappings/Reports/Timeline events,
   prompt-injection screening, answer generation) is deterministic,
   pre-answer-generation processing with no new agent/graph run involved —
   it never triggers a new investigation, only reads what one already
   produced. Unlike 4a-4i, this module also imports
   `core.memory.conversation_memory` (chat turn storage) and
   `core.security.prompt_guard` (the question is untrusted text,
   constitution §10) — both already-shipped modules from other layers, not
   new leaf packages built for this exception. ADR-0027 extends this
   exception with `core.memory.{long_term, manager}` (cross-case "similar
   past investigations" retrieval, always advisory) and
   `core.knowledge.{registry, retrieval, models}` (read-only Knowledge Layer
   search — OWASP/best-practice/detection-engineering guidance the chat can
   cite) — both read-only lookups gated by `ToolSelectionEngine`'s existing
   category selection, never a new business decision made in this module.
   See `docs/adr/0025-ai-investigation-assistant-conversational-interface.md`
   and `docs/adr/0027-production-memory-embedding-chat-provider-infrastructure.md`.
   No other `core/services` module gets this exception without its own ADR.

4k. **`core/services/report_export_service.py` may import `core/reporting`
   directly** — the eleventh documented exception to "services only call
   `core/graph`," worded identically to 4a-4j's established shape.
   Rendering an already-persisted `GeneratedReport` to a concrete file
   format (PDF/HTML/Markdown/DOCX/JSON) is deterministic, no-LLM-reasoning
   post-processing over data the Report Generator Agent already produced
   and `core/db/report_repository.py` already persisted — it never
   triggers a new investigation, never regenerates report content, and
   never touches `core/memory`/`core/security` (unlike 4j, export has no
   untrusted-input-screening or chat-history dimension). See
   `docs/adr/0026-report-export-framework.md`. No other `core/services`
   module gets this exception without its own ADR.

4. **`core/agents` may import `core/tools`, `core/parsers`, `core/knowledge`,
   `core/memory`, `core/security`, and — as the one explicit exception to
   "leaves never call up" — `core/graph/state.py` specifically (not
   `core/graph/investigation_graph.py`, `routing.py`/`router.py`, or
   `workflow_engine.py`). `CaseInvestigationState` is a shared leaf
   *contract*, not graph business logic: constitution §4.1 mandates every
   agent's literal signature be `(state: CaseInvestigationState) -> CaseInvestigationState`,
   which is impossible to type without importing it. Treat
   `core/graph/state.py` as belonging to the same "shared contract" leaf
   category as the root-level `core/exceptions.py`, `core/schemas.py`,
   `core/interfaces.py` (see `docs/adr/0009-multi-agent-framework-shape.md`
   point 7). Agents never import `core/db` directly — persistence happens
   through `core/services` or a repository function `core/graph` calls,
   keeping agents unaware of SQL/ORM details.

5. **`core/tools`, `core/parsers`, `core/threat_intel`, `core/findings`,
   `core/vulnerabilities`, `core/linux_security`, `core/linux_advisor`,
   `core/owasp_web`, and `core/owasp_security` may import
   `core/knowledge`** (e.g. `core/vulnerabilities/severity.py`/`extractor.py`
   use `core/knowledge/cvss_calculator.py`; `core/findings`'s mapping engine
   uses `core/knowledge/mitre`) **but never `core/agents`, `core/graph`, or
   `core/memory`.** These are leaves — nothing calls up from them, and they
   call nothing above them. `core/linux_security` does not currently import
   `core/knowledge` — unlike `core/vulnerabilities`'s CVSS dependency, no
   module in this package needs reference data from that layer; this is
   noted here only so a future contributor doesn't assume every leaf in this
   list exercises every permission it's granted. `core/linux_advisor`
   likewise imports neither `core/knowledge` nor `core/memory` — it has no
   reference-data dependency and no advisory/note-taking behavior
   (`docs/adr/0019-linux-security-advisor-agent.md` point 3). `core/owasp_web`
   imports neither `core/knowledge` nor `core/memory` for the identical
   reason (`docs/adr/0020-owasp-web-security-agent.md` point 3) — its OWASP
   category name/description lookup (`category_mapper.py`) is small enough
   to live inside the package itself rather than in `core/knowledge`.
   `core/owasp_security` likewise imports neither `core/knowledge` nor
   `core/memory` for the identical reason
   (`docs/adr/0021-owasp-security-agent-ast-sast.md` point 3) — its
   CWE/OWASP mapping tables (`models.py`) are small enough to live inside
   the package itself.
   `core/threat_intel`,
   `core/findings`, and `core/vulnerabilities` are the documented exceptions
   allowed to import another leaf's *model* contract sideways: `core/threat_intel`
   imports `core.parsers.models.NormalizedEvidence` (its input type), matching
   the precedent `core/db/models/evidence.py` already set by importing
   `core.parsers.models.EvidenceType`; `core/findings` imports
   `core.threat_intel.models.ScoredIOC`/`IOCRecord`/`IOCType` (its input
   type); `core/vulnerabilities/extractor.py` imports
   `core.parsers.models.{EvidenceRecord, NormalizedEvidence}` (its input
   type), the identical pattern applied a third time; `core/linux_security`
   applies the same pattern a fourth time, importing
   `core.parsers.models.{EvidenceRecord, NormalizedEvidence}` in
   `normalizer.py` — see
   `docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`
   point 1, `docs/adr/0013-finding-mitre-intelligence-engine-shape.md`
   point 2, `docs/adr/0017-vulnerability-assessment-framework.md` point 5,
   and `docs/adr/0018-linux-security-threat-hunting-framework.md`.

5b. **`core/tools/ir_tools.py` may import `core/incident_response`
   directly** — a second, narrower instance of the same shape rule 5's blanket
   `core/knowledge` permission already establishes for every leaf, granted
   here to one specific file rather than the whole `core/tools` package
   (mirroring how `core/tools/mitre_tools.py` is the one `core/tools/*.py`
   file with a typed, non-dict-shaped input, for the identical reason: its
   `run()` is a thin wrapper around a leaf package's own engine —
   `core.incident_response.response_plan_engine.ResponsePlanEngine` here,
   `core.knowledge.mitre.lookup.MitreLookup` there — never a duplicate
   reimplementation). No other `core/tools/*.py` file gets this exception;
   every other tool in this package stays dict-shaped, matching `docs/adr/
   0017`-`0021`'s established "no cross-leaf import" precedent. See
   `docs/adr/0023-incident-response-agent.md`.

5c. **`core/tools/report_tools.py` may import `core/reporting` directly** —
   a third instance of the same shape rule 5b already establishes for
   `ir_tools.py`, granted here to one specific file rather than the whole
   `core/tools` package: its `run()` is a thin wrapper around
   `core.reporting.report_engine.ReportGenerationEngine`, never a duplicate
   reimplementation. `core/agents/report_generator_agent.py` also imports
   `core.reporting.inputs.ReportGenerationContext`/`core.reporting.models.
   {GeneratedReport, ReportType}` directly, to construct the typed
   `ReportGenerationInput` it hands to its tool — this mirrors
   `core/agents/incident_response_agent.py`'s identical, already-shipped
   precedent of importing `core.incident_response.inputs.IncidentInputFinding`/
   `core.incident_response.models.{IncidentResponsePlan, IncidentSeverity}`
   directly for the same reason (constructing typed tool-call arguments),
   not a new kind of exception. No other `core/tools/*.py` file gets this
   exception; every other tool in this package stays dict-shaped, matching
   `docs/adr/0017`-`0021`'s established "no cross-leaf import" precedent.
   See `docs/adr/0024-report-generator-agent.md`.

6. **`core/memory` is the only layer allowed to import a vector-store client
   (ChromaDB).** No other layer talks to ChromaDB directly.

7. **`core/db` is the only layer allowed to import SQLAlchemy models
   directly for writes.** Agents and tools receive/return Pydantic models;
   translation to/from ORM rows happens in `core/services` or a dedicated
   repository function, never inline in an agent.

8. **`core/security` has no outbound dependency on any other `core/`
   subpackage** other than `core/config` (for pattern-list overrides). It is
   called *by* agents and services, never the reverse — a guardrail that
   itself depends on business logic could be bypassed by that logic changing.

9. **`core/config` is a leaf with zero internal dependencies.** Every other
   module may depend on it; it depends on nothing in `core/` or `apps/`.

10. **No circular imports, period.** If two modules seem to need each other,
    the shared concept is missing a home — extract it to `core/knowledge` (if
    it's data/reference) or introduce a new leaf module, don't create a cycle.

## Why this shape

- **Testability:** every layer below `core/services` is unit-testable with
  no database, no HTTP server, no browser.
- **Swappability:** the frontend (rule 2) and the persistence technology
  (rule 7) can each change without touching agent logic.
- **Auditability:** security guardrails (rule 8) can't be silently
  circumvented by a change elsewhere in the dependency graph, because nothing
  they depend on can be manipulated by the code they're guarding.

## Enforcement

`scripts/check_dependency_rules.py` statically scans `core/**/*.py` import
statements and fails if any module imports `streamlit`, `fastapi`, or a
sibling `core/` subpackage outside the allowed edges above. Wired into
`.pre-commit-config.yaml` and `.github/workflows/ci.yml`.
