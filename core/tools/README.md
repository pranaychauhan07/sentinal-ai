# core/tools — Deterministic Function-Calling Tools

**Purpose:** The Tool Layer (`context/01_blueprint.md` §4). Every deterministic
calculation an agent needs — log pattern detection, CVSS interpretation, MITRE
lookups, risk scoring — lives here as a plain, unit-testable Python function,
never as LLM-computed arithmetic (see `docs/adr/0008-agent-tool-boundary.md`).

**Responsibility:** One module per capability area (`log_tools.py`,
`phishing_tools.py`, `vuln_tools.py`, `owasp_tools.py`, `linux_tools.py`,
`ir_tools.py`, `mitre_tools.py`) plus `scoring.py` — the single source of truth
for the 0–100 risk-scoring math used across every module.

**Implemented (Multi-Agent Framework, `docs/adr/0009-multi-agent-framework-shape.md`):**
`base.py` (`BaseTool` — template-method base handling validation, timeout,
permission checks, retry-on-I/O-failure, caching, logging) and `registry.py`
(`ToolRegistry` — the seam a future MCP tool source plugs into).

**Implemented (Milestone M1, `docs/adr/0014-case-model-and-first-api-routes-shape.md`):**
`scoring.py` (`RiskScoringTool`, `ScoringWeights` — the SOC Analyst Agent's
deterministic 0-100 risk-scoring math, scoped to raw evidence-artifact
aggregate signal, distinct from and never duplicating `core/findings/
severity.py`'s already-implemented IOC/Finding-level `calculate_risk_score`).

**Implemented (Milestone M2, `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`):**
`phishing_tools.py` (`PhishingScoringTool`, `PhishingScoringWeights` — the
Phishing Agent's deterministic 0-100 risk-scoring math on its own
independent scale: sender/reply-to domain mismatch, urgency/social-
engineering phrase density, high-risk attachment extensions, combined with
the case's already-scored attributed URL/domain/email IOC composite scores.
Never re-extracts an IOC or recomputes a threat score itself).

**Implemented (Milestone M4, `docs/adr/0017-vulnerability-assessment-framework.md`):**
`vuln_tools.py` (`VulnerabilityAssessmentTool` — aggregates the case's
already-generated `VulnerabilityFinding` data (severity, priority, CVSS,
composite score — all computed by
`core.services.vulnerability_service.VulnerabilityPipeline`) into a
case-level summary: counts by severity, highest composite score, and a
top-N list by priority. Never recomputes CVSS, severity, or a threat score
itself).

**Implemented (Milestone M4, `docs/adr/0018-linux-security-threat-hunting-framework.md`):**
`linux_security_tools.py` (`LinuxSecurityAssessmentTool` — aggregates the
case's already-generated `LinuxSecurityFinding` data (category, severity,
composite score — all computed by
`core.services.linux_security_service.LinuxSecurityPipeline`) into a
case-level summary: counts by category/severity, highest composite score,
and a top-N list by severity. Never recomputes a detection, confidence, or
risk score itself). Backs `core.agents.threat_hunter_agent.ThreatHunterAgent`
(blueprint §7's Threat Hunting Agent) — not the same as the still-unbuilt
`linux_tools.py` (blueprint §7's narrow Linux Security Agent: command
explainer, permission-string analyzer).

**Implemented (Milestone M4, `docs/adr/0019-linux-security-advisor-agent.md`):**
`linux_tools.py` (`LinuxSecurityAdvisoryTool` — blueprint §7's actual named
file for the Linux Security Agent. Aggregates the case's already-analyzed
command/permission risk data and hardening recommendations (all computed by
`core.services.linux_advisor_service`/`core.linux_advisor`) into a
case-level summary: counts by severity, hardening recommendation counts
(baseline vs. finding-triggered), and the top-N highest-severity findings.
Never recomputes a command's risk, a permission's risk, or the overall risk
score itself). Backs `core.agents.linux_security_agent.LinuxSecurityAgent` —
**not** `linux_security_tools.py` above, which backs the different
`ThreatHunterAgent`.

**Implemented (Milestone M4, `docs/adr/0020-owasp-web-security-agent.md`):**
`web_security_tools.py` (`WebSecurityAdvisoryTool` — aggregates the case's
already-analyzed OWASP-mapped header/cookie/JWT/misconfiguration finding
data (all computed by `core.services.web_security_service`/
`core.owasp_web`) into a case-level summary: counts by OWASP category and
severity, and the top-N highest-severity findings. Never recomputes a
finding's severity, confidence, or the overall risk score itself). Backs
`core.agents.web_security_agent.WebSecurityAgent` — **not** blueprint §7's
`owasp_tools.py` (the AST-based source-code static analyzer's tool, built
this session below), which this deliberately never touches or renames.

**Implemented (Milestone M4, `docs/adr/0021-owasp-security-agent-ast-sast.md`):**
`owasp_tools.py` (`OwaspSecurityAssessmentTool` — blueprint's exact named
file. Aggregates the case's already-analyzed AST/pattern-based SAST finding
data (all computed by `core.services.owasp_security_service`/
`core.owasp_security`) into a case-level summary: counts by OWASP category/
CWE/severity, and the top-N highest-severity findings. Never recomputes a
finding's severity, confidence, or the overall risk score itself). Backs
`core.agents.owasp_security_agent.OwaspSecurityAgent` — **not**
`web_security_tools.py` above, which backs the different `WebSecurityAgent`.

No other concrete tool (`log_tools.py`, `ir_tools.py`, `mitre_tools.py`)
exists yet.

**Why it exists:** Keeps agents honest — an agent's job is to decide *which*
tool to call and interpret the result, not to do the math itself.

**Future expansion:** A future Sigma-rule engine (`docs/roadmap.md` — Future
Expansion) would replace the hardcoded detection functions in `log_tools.py`
without changing any agent.
