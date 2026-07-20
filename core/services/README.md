# core/services — Orchestration Layer for Frontends

**Purpose:** The thin layer both `apps/web` (Streamlit) and `apps/api`
(FastAPI) call. `case_service.py` (create/list/run investigations on a case),
`evidence_service.py` (upload/classify evidence), `threat_intel_service.py`
(extract/score/classify IOCs from evidence), `finding_service.py` (map IOCs
to MITRE ATT&CK, generate/dedup/persist Findings),
`vulnerability_service.py` (extract/score/correlate/generate findings from
Nessus/OpenVAS scan reports), `report_service.py` (generate/fetch reports).

**Responsibility:** Translates a frontend request into calls against
`core/graph`, `core/db`, and `core/reporting` — and nothing else, with five
documented exceptions: `evidence_service.py` also calls `core/parsers`
directly (evidence ingestion is deterministic, pre-investigation processing
with no agent/LLM reasoning — see `docs/adr/0011-evidence-ingestion-pipeline-shape.md`
and `docs/dependency-rules.md` rule 4a); `threat_intel_service.py` calls
`core/threat_intel` and `core/parsers` directly for the identical reason (IOC
extraction is also deterministic, pre-investigation processing — see
`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md` and
`docs/dependency-rules.md` rule 4b); `finding_service.py` calls
`core/findings`, `core/threat_intel` (models only), and `core/knowledge`
directly for the same reason (MITRE mapping and Finding generation are also
deterministic, pre-investigation processing — see
`docs/adr/0013-finding-mitre-intelligence-engine-shape.md` and
`docs/dependency-rules.md` rule 4c); `case_service.py` calls
`core.agents.{registry, soc_analyst_agent, phishing_agent,
vulnerability_agent}`, `core.memory.{case_memory, repository}`, and
`core.parsers.models` (types only) directly, to build a session-scoped
`CaseMemory` and a fresh `AgentRegistry` before delegating to `core/graph` —
see `docs/adr/0014-case-model-and-first-api-routes-shape.md` and
`docs/dependency-rules.md` rule 4d; and `vulnerability_service.py` calls
`core/vulnerabilities` and `core/parsers` directly for the same
"deterministic, pre-investigation processing" reason as 4b — see
`docs/adr/0017-vulnerability-assessment-framework.md` and
`docs/dependency-rules.md` rule 4e. All five also call `core/memory` (the
same "check Memory for similar past cases"/case-note pattern this README
already documented as a services-level concern). This is the one place
business rules that span multiple subsystems are coordinated —
`case_service.py`'s `investigate_new_evidence()` is the first real example:
it composes `evidence_service`, `threat_intel_service`, `finding_service`,
`vulnerability_service` (for scan-report evidence only), and a `core/graph`
run of the matching specialist agent into one blueprint §9 pipeline,
recording a `TimelineEvent` at each stage.

**`vulnerability_service.py` (docs/adr/0017-vulnerability-assessment-
framework.md):** `VulnerabilityPipeline` — the ten-stage assessment
pipeline (extract -> validate -> normalize -> deduplicate -> correlate ->
score -> generate_findings -> persist -> publish_event -> notify_memory),
mirroring `threat_intel_service.IOCExtractionPipeline`'s shape exactly.
`assess_vulnerabilities()` composes it into the one call `case_service.py`
invokes, gated to actual scan-report evidence types only (running it
against a log/email would only ever produce rejected candidates).

**ADR-0015 (Case Management Extension):** `case_service.py` gained case
ownership/priority/tags/notes mutation functions and case-level risk-score
recomputation, plus lifecycle-transition validation on `update_case_status`
(delegating to the new `case_lifecycle.py`). Three new sibling modules —
`case_lifecycle.py` (pure, exhaustively-tested `CaseStatus` transition
table), `case_events.py` (`CaseEvent`/`CaseEventPublisher`, mirroring
`core.findings.events`'s shape), and `case_metrics.py`
(`CaseMetricsCollector` + `compute_case_risk_score`, mirroring
`core.findings.metrics`'s shape) — live here rather than a new `core/cases/`
leaf package, since `Case` (unlike Evidence/IOC/Finding) has no multi-stage
deterministic engine of its own; its logic is orchestration, already this
layer's job. No new `docs/dependency-rules.md` exception was needed — see
`docs/adr/0015-case-management-extension.md`.

**Why it exists:** Guarantees Streamlit pages and FastAPI routers stay
interchangeable front doors to the same behavior — see `docs/dependency-rules.md`.

**Future expansion:** A CLI (`scripts/`) or a future integration would also
call these same services rather than duplicating logic.
