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
`planning_agent.py` (`PlanningAgent` — capability-based plan builder). No
specialist agent (SOC Analyst, Phishing, ...) exists yet — see
`docs/agent-design.md` for how to add one on top of this framework.

**Why it exists:** This is the Agent Layer from the architecture
(`context/01_blueprint.md` §4) — the "AI system" the whole project is built around.

**Future expansion:** New evidence types get a new specialist agent here;
existing agents gain tools, not inline logic.
