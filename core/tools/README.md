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
(`ToolRegistry` — the seam a future MCP tool source plugs into). No
concrete tool (`log_tools.py`, `scoring.py`, ...) exists yet.

**Why it exists:** Keeps agents honest — an agent's job is to decide *which*
tool to call and interpret the result, not to do the math itself.

**Future expansion:** A future Sigma-rule engine (`docs/roadmap.md` — Future
Expansion) would replace the hardcoded detection functions in `log_tools.py`
without changing any agent.
