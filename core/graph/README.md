# core/graph — LangGraph StateGraph Wiring

**Purpose:** Owns the Case Investigation Graph — the Workflow Layer from the
architecture (`context/01_blueprint.md` §4). This is where agents
(`core/agents/*`) are composed into the actual multi-agent workflow.

**Responsibility:** `state.py` defines `CaseInvestigationState` (the single typed
object every node reads/writes — no global mutation, ever). `investigation_graph.py`
wires nodes and edges. `routing.py` holds conditional-edge logic (e.g., route to
the Phishing Agent only if `evidence_type == email`).

**Implemented (Multi-Agent Framework, `docs/adr/0009-multi-agent-framework-shape.md`):**
`workflow_engine.py` (`WorkflowEngine` — compiles registered agents into a
LangGraph `StateGraph`, diffs each node's before/after state into a
reducer-safe partial update, wraps every node with retry/failure-recovery/
events), `routing.py` (`route_from_coordinator`), `investigation_graph.py`
(`build_investigation_graph`/`run_investigation` — today wires only the
Coordinator; specialist nodes are added here per milestone),
`execution_context.py` (run-scoped logging/timing context manager),
`events.py` (`EventBus`/`WorkflowEvent` pub-sub), `retry.py` (`RetryPolicy`),
`failure_recovery.py` (`FailureRecoveryPolicy`), `metrics.py`
(`MetricsCollector`/`WorkflowMetrics`). All framework-only — no domain
reasoning, no concrete specialist agent.

**Why it exists:** Makes control flow explicit and inspectable instead of buried
in imperative Python — this is what enables checkpointing, retries, and replay.

**Future expansion:** New agents are added as new nodes with new edges in
`investigation_graph.py`; the graph shape is expected to grow across
milestones M1→M6, with zero changes to `workflow_engine.py` or `routing.py`.
