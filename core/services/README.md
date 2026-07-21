# core/services — Orchestration Layer for Frontends

**Purpose:** The thin layer both `apps/web` (Streamlit) and `apps/api`
(FastAPI) call. `case_service.py` (create/list/run investigations on a case),
`evidence_service.py` (upload/classify evidence), `threat_intel_service.py`
(extract/score/classify IOCs from evidence), `finding_service.py` (map IOCs
to MITRE ATT&CK, generate/dedup/persist Findings),
`vulnerability_service.py` (extract/score/correlate/generate findings from
Nessus/OpenVAS scan reports), `linux_security_service.py` (analyze SSH-auth/
syslog evidence for brute force/sudo abuse/privilege escalation/persistence/
suspicious processes), `linux_advisor_service.py` (analyze raw Linux
command/`ls -l` input for dangerous commands, permission risks, and
hardening recommendations — no DB persistence), `web_security_service.py`
(analyze raw HTTP transaction transcripts for OWASP-mapped header/cookie/
JWT/misconfiguration issues — no DB persistence),
`owasp_security_service.py` (AST/pattern-based SAST analysis of source code
files for OWASP/CWE-mapped vulnerabilities — no DB persistence),
`report_service.py` (generate/fetch reports), `conversation_service.py`
(blueprint §13's AI Analyst Chat — answers a free-form, case-scoped
question grounded in already-persisted Findings/IOCs/MITRE mappings/
Reports/Timeline events via `core/conversation`'s deterministic pipeline;
never triggers a new investigation run).

**Responsibility:** Translates a frontend request into calls against
`core/graph`, `core/db`, and `core/reporting` — and nothing else, with eight
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
`docs/dependency-rules.md` rule 4d (ADR-0027 extended this to
`core.memory.{long_term, manager}`; ADR-0028 extends it again to
`core.memory.investigation_context` and `core.knowledge.{registry,
retrieval, models}` — the Memory Agent's read path,
`_hydrate_memory_context_record`); `vulnerability_service.py` calls
`core/vulnerabilities` and `core/parsers` directly for the same
"deterministic, pre-investigation processing" reason as 4b — see
`docs/adr/0017-vulnerability-assessment-framework.md` and
`docs/dependency-rules.md` rule 4e; `linux_security_service.py` calls
`core/linux_security` and `core/parsers` directly for the same reason — see
`docs/adr/0018-linux-security-threat-hunting-framework.md` and
`docs/dependency-rules.md` rule 4f; and `linux_advisor_service.py` calls
`core/linux_advisor` and `core/parsers` directly for the same reason — see
`docs/adr/0019-linux-security-advisor-agent.md` and
`docs/dependency-rules.md` rule 4g; and `web_security_service.py` calls
`core/owasp_web` and `core/parsers` directly for the same reason — see
`docs/adr/0020-owasp-web-security-agent.md` and `docs/dependency-rules.md`
rule 4h; and `owasp_security_service.py` calls `core/owasp_security` and
`core/parsers` directly for the same reason — see
`docs/adr/0021-owasp-security-agent-ast-sast.md` and
`docs/dependency-rules.md` rule 4i (these last three modules, uniquely,
never touch `core/memory` — they have no note-taking behavior and no DB
session parameter, since none of the three frameworks persist anything);
and `conversation_service.py` calls `core/conversation`, `core.memory.
conversation_memory`, and `core.security.prompt_guard` directly — a tenth
exception, worded identically, since case-scoped conversational retrieval
is also deterministic, pre-answer-generation processing with no new
agent/graph run involved (see `docs/adr/0025-ai-investigation-assistant-
conversational-interface.md` and `docs/dependency-rules.md` rule 4j).
The other six also call `core/memory` (the
same "check Memory for similar past cases"/case-note pattern this README
already documented as a services-level concern). This is the one place
business rules that span multiple subsystems are coordinated —
`case_service.py`'s `investigate_new_evidence()` is the first real example:
it composes `evidence_service`, `threat_intel_service`, `finding_service`,
`vulnerability_service` (for scan-report evidence only),
`linux_security_service` (for SSH-auth/syslog evidence only), and a
`core/graph` run of the matching specialist agent(s) into one blueprint §9
pipeline, recording a `TimelineEvent` at each stage.

**`vulnerability_service.py` (docs/adr/0017-vulnerability-assessment-
framework.md):** `VulnerabilityPipeline` — the ten-stage assessment
pipeline (extract -> validate -> normalize -> deduplicate -> correlate ->
score -> generate_findings -> persist -> publish_event -> notify_memory),
mirroring `threat_intel_service.IOCExtractionPipeline`'s shape exactly.
`assess_vulnerabilities()` composes it into the one call `case_service.py`
invokes, gated to actual scan-report evidence types only (running it
against a log/email would only ever produce rejected candidates).

**`linux_security_service.py` (docs/adr/0018-linux-security-threat-hunting-
framework.md):** `LinuxSecurityPipeline` — the ten-stage analysis pipeline
(Evidence Normalization -> Authentication Analysis -> Privilege Analysis ->
Persistence Analysis -> Behavior Detection -> Threat Scoring -> Finding
Generation -> Persistence -> Event Publication -> Case/Timeline
Notification), mirroring `VulnerabilityPipeline`'s shape exactly.
`assess_linux_security()` composes it into the one call `case_service.py`
invokes, gated to `SSH_AUTH`/`SYSLOG` evidence only — deliberately not
`EvidenceType.JSON` (JSON evidence is generic elsewhere in this codebase;
see the ADR for the full reasoning).

**`linux_advisor_service.py` (docs/adr/0019-linux-security-advisor-agent.md):**
`assess_linux_command_input()` — a synchronous, five-stage call (no DB
session parameter, since this framework never persists) composing
`core.linux_advisor.advisory_engine.LinuxSecurityAdvisoryEngine`: classify
each line -> analyze command/permission -> generate hardening
recommendations -> assess overall risk -> emit audit events.
`case_service.py` invokes it gated to `EvidenceType.LINUX_COMMAND_INPUT`
only.

**`web_security_service.py` (docs/adr/0020-owasp-web-security-agent.md):**
`assess_http_transaction()` — a synchronous call (no DB session parameter,
since this framework never persists) composing
`core.owasp_web.advisory_engine.WebSecurityAdvisoryEngine`: classify each
line (header/cookie/JWT/misconfiguration candidate) -> analyze -> normalize
into unified `OwaspFinding`s -> assess overall risk -> emit audit events.
`case_service.py` invokes it gated to `EvidenceType.HTTP_TRANSACTION` only.

**`owasp_security_service.py` (docs/adr/0021-owasp-security-agent-ast-sast.md):**
`assess_source_code()` — a synchronous call (no DB session parameter, since
this framework never persists) composing
`core.owasp_security.analysis_engine.SourceCodeAnalysisEngine`: detect
language -> AST-parse (Python) / pattern-match (JavaScript/TypeScript/Java)
-> generate secure-coding recommendations -> normalize into unified
`SastFinding`s -> assess overall risk -> emit audit events.
`case_service.py` invokes it gated to `EvidenceType.SOURCE_CODE` only.

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
