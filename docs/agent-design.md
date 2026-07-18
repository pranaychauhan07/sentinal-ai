# Agent Design

Full per-agent contracts (purpose, responsibilities, input/output types, tools
used, interactions, failure handling) are specified in
**[`context/01_blueprint.md`](../context/01_blueprint.md)** §7 and are the
authoritative spec for implementing each `core/agents/*.py` module. This
document adds the engineering conventions every agent implementation must
follow — it does not repeat the per-agent contracts already written there.

## Conventions every agent follows

1. **Typed I/O only.** Every agent's node function signature is
   `(state: CaseInvestigationState) -> CaseInvestigationState`, and every
   field it reads/writes on that state is a Pydantic model — never a raw
   dict or free-text blob standing in for structured data.

2. **Explicit `Thought` field.** Every agent output includes a human-readable
   `thought: str` explaining its reasoning, independent of any final
   `verdict`/`finding` field. This is what the UI's Investigation Trail
   renders and what makes ReAct reasoning inspectable rather than just
   prompted-for narration.

3. **Tools do the math.** An agent decides *which* tool in `core/tools/` to
   call and interprets the result; it never computes a CVSS score or risk
   score inline via LLM arithmetic (see `docs/adr/0008-agent-tool-boundary.md`).

4. **Confidence is mandatory.** Any inference weaker than a deterministic
   parse (LLM-fallback parsing, low-evidence MITRE mapping) carries an
   explicit `confidence: float` so downstream consumers and the human analyst
   know when to double-check.

5. **Untrusted text passes through the guard first.** Any agent that includes
   attacker-or-third-party-authored text (phishing body, uploaded source
   code) in a prompt calls `core/security/prompt_guard.py` on it first — no
   exceptions, no "just this once."

6. **"Not found" ≠ "couldn't tell."** Agents distinguish an explicit negative
   result (e.g. "no IOCs found") from insufficient evidence to conclude
   ("log coverage too sparse to assess") — never silently collapse the two.

7. **Failure degrades, never crashes the case.** Per-agent failure handling
   (blueprint §7) always has a documented fallback path (manual triage flag,
   sequential default order, "unmapped" MITRE result, etc.) rather than an
   unhandled exception propagating out of the graph.

## The framework every agent is built on

`core/agents/base.py`'s `BaseAgent` implements every convention above
mechanically (see `docs/adr/0009-multi-agent-framework-shape.md` for the
full design rationale). A concrete agent only ever implements `execute()`:

- **Identity** is class attributes (`name`, `description`,
  `responsibilities`, `capabilities`, `tools_used`) — never computed at
  runtime, so the `AgentRegistry`/Planning Agent can introspect an agent
  without invoking it.
- **`__call__`** (the constitution §4.1 entry point) is final — never
  overridden. It binds logging context, times the invocation, catches
  every exception `execute()` can raise and converts it to a degraded
  result (never lets one escape into the graph), and records the ReAct
  `thought`/`confidence`/`ExecutionMetadata` onto `CaseInvestigationState`
  uniformly.
- **Tool access** is `self.use_tool(name, arguments)` — raises if `name`
  isn't in the agent's own declared `tools_used`, so "which tools can this
  agent call" is checkable by reading the class, not by tracing what
  happens to be imported.
- **Memory access** is an optional `case_memory` constructor argument typed
  against `core/memory/interfaces.py`'s `CaseMemory` Protocol — no
  implementation exists yet (Milestone M6), and every agent must work
  correctly with `case_memory=None`.

## How an agent joins the graph

`core/agents/coordinator.py` and `core/agents/planning_agent.py` are
themselves the first two `BaseAgent` implementations, and they establish the
pattern every specialist agent follows: the Planning Agent matches
`state.metadata["required_capabilities"]` (a list of capability-name
strings) against every registered agent's declared `AgentCapability`
entries and writes an `ExecutionPlan`; `core/graph/routing.py`'s
`route_from_coordinator` reads that plan to decide which registered graph
nodes run next. A specialist agent joins this system by declaring a
capability — no change to the Coordinator, Planning Agent, or
`WorkflowEngine` is needed.

## Adding a new agent

1. Add the Pydantic input/output models next to the agent module (`output`
   on `AgentExecutionResult` is a generic `dict[str, Any]` at the framework
   layer — a concrete agent should still validate/build it from a real
   Pydantic model internally, not hand-construct a raw dict, matching
   constitution §4.3).
2. Subclass `BaseAgent`, implement `execute()` only. Declare `name`,
   `description`, `responsibilities`, `capabilities` (the string tag(s)
   the Planning Agent should match this agent against), and `tools_used`.
3. Register an instance in an `AgentRegistry` (production code uses
   `core.agents.registry.default_agent_registry()`).
4. Wire it into `core/graph/investigation_graph.py`:
   `engine.add_agent_node(YourAgent.name)` plus
   `engine.add_edge(YourAgent.name, END)` (or further conditional routing
   if it fans out to something else). No other framework file changes.
5. Add unit tests for any new tool it depends on, an agent-level test
   invoking the node function directly (per constitution §11), plus an
   integration test in `tests/integration/` exercising the new node inside
   a full graph run.
6. Document it: append a section to blueprint §7's agent list conceptually
   (the blueprint itself is not edited retroactively — add a new ADR if the
   change is architecturally significant, otherwise this file's conventions
   already cover it).
