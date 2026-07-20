# core/agents — LangGraph Agent Nodes

**Purpose:** The 12 specialist/support agents defined in the blueprint
(`docs/agent-design.md`): Coordinator, Planning, Parser/Evidence, SOC Analyst,
Threat Hunting, Phishing Investigation, Vulnerability Assessment, OWASP Security,
Linux Security, Incident Response, MITRE Mapping, Report Generator, Memory.

**Responsibility:** Each agent is a LangGraph node with a strict Pydantic
input/output contract and an explicit `Thought` field (ReAct reasoning, logged
and shown in the UI's Investigation Trail). Agents call `core/tools/*` for any
deterministic computation — they never compute CVSS/risk scores themselves.

**Typical files:** One module per agent (`coordinator.py`, `soc_analyst_agent.py`,
etc.), each exporting a single LangGraph-compatible node function plus its
Pydantic I/O models.

**Implemented (Multi-Agent Framework, `docs/adr/0009-multi-agent-framework-shape.md`):**
`base.py` (`BaseAgent` — the template-method base every agent, including
these two, inherits from), `registry.py` (`AgentRegistry`), `confidence.py`
(`ConfidenceScore`/`ConfidenceLevel`), `contracts.py` (`ExecutionPlan`,
`AgentExecutionResult`, `AgentCapability`, etc.), `coordinator.py`
(`CoordinatorAgent` — delegates planning, never executes agents itself),
`planning_agent.py` (`PlanningAgent` — capability-based plan builder).

**Implemented (Milestone M1, `docs/adr/0014-case-model-and-first-api-routes-shape.md`):**
`soc_analyst_agent.py` — the first concrete specialist agent
(`SocAnalystAgent`), declaring capability `log_analysis`. Calls
`core.tools.scoring.RiskScoringTool` (never computes risk scores itself) to
summarize each `NormalizedEvidence` artifact's event volume, severity
distribution, and flag suspected brute-force patterns from source
concentration. Its `SocFinding[]` output lives on
`CaseInvestigationState.findings` (the in-memory ReAct trail), not the
persisted `findings` DB table — see the ADR for why.

**Implemented (Milestone M2, `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`):**
`phishing_agent.py` — the second concrete specialist agent (`PhishingAgent`),
declaring capability `email_triage`. Screens email subject/body through
`core.security.prompt_guard.scan_text` before using that text for anything
else (the first agent consuming attacker-controlled text), then calls
`core.tools.phishing_tools.PhishingScoringTool` (never re-extracting IOCs or
recomputing threat scores itself) to produce a `PhishingVerdict[]`, appended
to `CaseInvestigationState.findings` the same way `SocFinding[]` is. Reads
already-scored, already-attributed URL/domain/email IOCs from
`CaseInvestigationState.extracted_indicators` as plain
`dict[str, object]` entries — deliberately *not* a typed
`core.threat_intel.models.ScoredIOC` import, since `docs/dependency-rules.md`
rule 4 grants `core/agents` no import edge onto `core/threat_intel`.

**Implemented (Milestone M4, `docs/adr/0017-vulnerability-assessment-framework.md`):**
`vulnerability_agent.py` — the third concrete specialist agent
(`VulnerabilityAssessmentAgent`), declaring capability
`vulnerability_assessment`. Deliberately thin: all CVSS scoring, severity
classification, deduplication, asset correlation, and finding generation
already happened in `core.services.vulnerability_service.
VulnerabilityPipeline` *before* this agent runs (mirroring how IOC
extraction precedes `SocAnalystAgent`). Calls
`core.tools.vuln_tools.VulnerabilityAssessmentTool` to aggregate the case's
already-generated `VulnerabilityFinding`s (read from
`CaseInvestigationState.vulnerability_records` as plain `dict[str, object]`
entries — same "no `core/threat_intel`/`core/vulnerabilities` import edge"
reasoning `phishing_agent.py`'s docstring documents) into a case-level
`VulnerabilityAssessment`, appended to `CaseInvestigationState.findings` the
same way `SocFinding[]`/`PhishingVerdict[]` are.

**Implemented (Milestone M4, `docs/adr/0018-linux-security-threat-hunting-framework.md`):**
`threat_hunter_agent.py` — the fourth concrete specialist agent
(`ThreatHunterAgent`), declaring capability `cross_log_threat_hunting`.
Blueprint §7's Threat Hunting Agent, concretely delivered this session as
the Linux-log-based detection surface: SSH brute force/compromise, sudo
abuse, privilege escalation, persistence, and suspicious-process detection
over `SSH_AUTH`/`SYSLOG` evidence. Deliberately thin: every detection,
confidence, and risk score already happened in
`core.services.linux_security_service.LinuxSecurityPipeline` *before* this
agent runs (mirroring `VulnerabilityAssessmentAgent`'s precedent). Calls
`core.tools.linux_security_tools.LinuxSecurityAssessmentTool` to aggregate
the case's already-generated `LinuxSecurityFinding`s (read from
`CaseInvestigationState.linux_security_records` as plain `dict[str, object]`
entries — same "no `core/linux_security` import edge" reasoning
`vulnerability_agent.py`'s docstring documents) into a case-level
`ThreatHuntingReport`, appended to `CaseInvestigationState.findings` the same
way `SocFinding[]`/`PhishingVerdict[]`/`VulnerabilityAssessment` are. **Not**
the blueprint §7 Linux Security Agent (a narrow command/permission-string
explainer) — that agent remains unbuilt, separate, still-open M4 scope.

**Implemented (Milestone M4, `docs/adr/0019-linux-security-advisor-agent.md`):**
`linux_security_agent.py` — the fifth concrete specialist agent
(`LinuxSecurityAgent`), declaring capability `linux_security_advisory`.
Blueprint §7's actual Linux Security Agent (the narrow command/permission
advisor — **not** `threat_hunter_agent.py`'s log-based detection). Reads raw
command/`ls -l` input via `EvidenceType.LINUX_COMMAND_INPUT`. Deliberately
thin: all command tokenization, permission parsing, rule evaluation, and
risk scoring already happened in
`core.services.linux_advisor_service.assess_linux_command_input` *before*
this agent runs. Calls `core.tools.linux_tools.LinuxSecurityAdvisoryTool` to
aggregate the case's already-computed advisory data (read from
`CaseInvestigationState.linux_advisory_records` as plain `dict[str, object]`
entries — a **different** field name from `linux_security_records`, which
`ThreatHunterAgent` already uses, so the two frameworks' outputs never
collide) into a case-level `LinuxSecurityAdvice` (blueprint's exact named
output type), appended to `CaseInvestigationState.findings` the same way
every prior specialist agent's output is.

**Implemented (Milestone M4, `docs/adr/0020-owasp-web-security-agent.md`):**
`web_security_agent.py` — the sixth concrete specialist agent
(`WebSecurityAgent`), declaring capability `owasp_web_security_assessment`.
A new, out-of-blueprint capability — **not** blueprint §7's OWASP Security
Agent (the AST-based source-code/API static reviewer, still unbuilt; see
ADR-0020 for why the two are deliberately separate). Reads HTTP traffic
input via `EvidenceType.HTTP_TRANSACTION`. Deliberately thin: all header/
cookie/JWT/misconfiguration analysis, OWASP category mapping, and risk
scoring already happened in
`core.services.web_security_service.assess_http_transaction` *before* this
agent runs. Calls `core.tools.web_security_tools.WebSecurityAdvisoryTool` to
aggregate the case's already-computed OWASP-mapped findings (read from
`CaseInvestigationState.owasp_web_records` as plain `dict[str, object]`
entries — a distinct field name from every other `*_records` field) into a
case-level `WebSecurityAdvice`, appended to `CaseInvestigationState.findings`
the same way every prior specialist agent's output is.

**Implemented (Milestone M4, `docs/adr/0021-owasp-security-agent-ast-sast.md`):**
`owasp_security_agent.py` — the seventh concrete specialist agent
(`OwaspSecurityAgent`), declaring capability `owasp_source_code_review`.
Blueprint §7's actual OWASP Security Agent (source code / API static
review, AST-based) — **not** `web_security_agent.py`'s HTTP-traffic
analysis (ADR-0020); the two never import each other. Reads source code
input via `EvidenceType.SOURCE_CODE`. Deliberately thin: all language
detection, AST parsing (Python)/pattern matching (JavaScript/TypeScript/
Java), rule evaluation, secure-coding advice, and risk scoring already
happened in `core.services.owasp_security_service.assess_source_code`
*before* this agent runs. Calls
`core.tools.owasp_tools.OwaspSecurityAssessmentTool` to aggregate the
case's already-computed OWASP/CWE-mapped findings (read from
`CaseInvestigationState.owasp_security_records` as plain `dict[str, object]`
entries — a distinct field name from every other `*_records` field) into a
case-level `SastAdvice`, appended to `CaseInvestigationState.findings` the
same way every prior specialist agent's output is. This closes M4 entirely.

No other specialist agent (Incident Response, ...) exists yet — see
`docs/agent-design.md` for how to add one on top of this framework.

**Why it exists:** This is the Agent Layer from the architecture
(`context/01_blueprint.md` §4) — the "AI system" the whole project is built around.

**Future expansion:** New evidence types get a new specialist agent here;
existing agents gain tools, not inline logic.
