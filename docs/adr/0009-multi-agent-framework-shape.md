# ADR-0009: Multi-Agent Framework Shape (Registries, BaseAgent/BaseTool, Coordinator/Planner Split, Reducer-Based Parallel State)

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

ADR-0003 already chose LangGraph as the orchestration engine. It did not
decide the concrete shape of the reusable framework built on top of it:
how agents/tools self-register, where retry/failure-recovery/observability
live, how the Coordinator and Planning agents (blueprint §7) divide
responsibility, or how `CaseInvestigationState` survives concurrent writes
from independently-scheduled specialist agents. This was built ahead of the
milestone schedule (`docs/roadmap.md` places it at M3, after M1's first
concrete agent) at the user's explicit direction — build the reusable
agent/tool/workflow infrastructure before any domain-specific agent exists,
so it is validated by its own tests rather than retrofitted around one
agent's assumptions. That reordering, and the concrete design decisions
below, needed to be recorded before implementation, per constitution §12.

## Decision

1. **Registries, not global state.** `AgentRegistry` (`core/agents/registry.py`)
   and `ToolRegistry` (`core/tools/registry.py`) are explicit, injectable
   classes with a documented `lru_cache`-backed process-wide singleton
   accessor (`default_agent_registry()`/`default_tool_registry()`),
   matching `core.config.get_settings()`'s existing sanctioned pattern
   (constitution §2, "Avoid global state").

2. **`BaseAgent`/`BaseTool` as template methods.** Concrete agents/tools
   implement only `execute()`/`run()`; the base class owns validation,
   logging, confidence/metadata bookkeeping, and — for tools — timeout,
   retry-on-I/O-failure, caching, and permission checks. This is what makes
   constitution §4 (agent contract) and §5 (tool contract) true by
   construction rather than by convention.

3. **Coordinator delegates planning; it does not execute agents itself.**
   `CoordinatorAgent.execute()` calls `PlanningAgent` directly (a plain
   Python call within `core/agents`, not a graph edge) and writes the
   resulting `ExecutionPlan` onto `CaseInvestigationState.execution_plan`.
   Actually running the planned specialist agents — sequencing, fan-out,
   merging results — is `core/graph/routing.py` and
   `core/graph/workflow_engine.py`'s job, expressed as real LangGraph nodes
   and conditional edges. This matches blueprint §7's Coordinator card
   literally ("Output: InvestigationPlan ... Tools used: none directly —
   it calls the Planning Agent") and this milestone's explicit instruction
   that "the coordinator should never perform domain-specific reasoning" —
   extended here to mean it never performs *execution* either, only
   planning delegation.

4. **Two-tier error handling, matching constitution §9 exactly.**
   `BaseAgent._execute_safely` catches everything a concrete agent's
   `execute()` can raise and converts it to a degraded/failed
   `AgentExecutionResult` — this is the *documented* fallback tier.
   `core/graph/workflow_engine.py` wraps every node with its own
   `RetryPolicy`/`FailureRecoveryPolicy` for the *undocumented* tier: a
   genuinely unexpected exception escaping `BaseAgent.__call__` itself (a
   framework bug, not an agent failure mode). Constitution §9 describes
   exactly this split ("core/graph ... catch only truly unexpected
   exceptions ... and convert them into a case-level state rather than
   crashing") — it was not obvious in advance that both tiers were needed
   until the retry/failure-recovery framework pieces were actually built
   and it became clear `BaseAgent`'s own catch-all left workflow_engine's
   retry logic almost never triggering for ordinary agent failures. Kept
   anyway as the correct defense-in-depth for framework-level bugs.

5. **Reducer-based shared state for parallel fan-out — verified empirically,
   not assumed.** `CaseInvestigationState`'s list/dict fields
   (`core/graph/state.py`) are `Annotated[..., operator.add]` /
   `Annotated[..., _merge_dicts]` so LangGraph can run independent
   specialist agents in the same superstep without raising
   `InvalidUpdateError`. Before relying on this, two behaviors were tested
   directly against the installed `langgraph` package (not assumed from
   documentation):
   - Naive nodes returning a full replacement state conflict under
     concurrent execution even with reducers, because
     `CaseInvestigationState` fields not touched by a given agent still
     appear as concurrent writes when the node returns the whole object.
   - LangGraph shares the *same* input object across sibling nodes
     scheduled in one superstep rather than deep-copying per branch — so a
     node that mutates its input parameter in place (as `BaseAgent`
     naturally does, since `CaseInvestigationState` is mutable) can corrupt
     a sibling's "before" snapshot depending on execution order, causing
     duplicated entries. This was caught by an integration-style scratch
     test *before* it reached the checked-in test suite.

   The fix implemented in `core/graph/workflow_engine.py`: every node
   operates on its own `state.model_copy(deep=True)` and diffs the result
   against the *original*, never-mutated `state` parameter, returning only
   the changed slice as a partial update. This makes the framework correct
   under real LangGraph parallel scheduling regardless of whichever
   internal object-sharing behavior a future LangGraph version uses.

6. **Memory: interfaces only.** `core/memory/interfaces.py` defines
   `ShortTermMemory`/`CaseMemory`/`LongTermMemory`/`VectorMemory` as
   `Protocol`s with zero implementation, per this milestone's explicit
   scope. `BaseAgent` accepts an optional `CaseMemory` dependency and works
   identically with none, preserving the existing "memory is always
   advisory" rule (`docs/adr/0006-memory-strategy.md`).

7. **Clarifying, not amending, a pre-existing dependency-rule gap.**
   `docs/dependency-rules.md` rule 4 lists what `core/agents` may import
   (`core/tools`, `core/parsers`, `core/knowledge`, `core/memory`,
   `core/security`) but omits `core/graph/state.py` — even though
   constitution §4.1 mandates every agent's literal signature be
   `(state: CaseInvestigationState) -> CaseInvestigationState`, which is
   impossible to type without importing it, and `core/interfaces.py`'s own
   docstring already anticipated `Agent[CaseInvestigationState]`. This ADR
   records the resolution: `core/graph/state.py` (the state *definition*)
   is treated as a shared leaf contract importable by `core/agents`,
   identical in kind to the existing root-level `core/exceptions.py`,
   `core/schemas.py`, `core/interfaces.py` exception already carved out in
   `context/current_state.md`. `core/graph/investigation_graph.py`,
   `router.py`, and `workflow_engine.py` remain off-limits to
   `core/agents` — only `state.py` is the exception, and `docs/dependency-rules.md`
   is updated in the same change to say so explicitly, closing the gap
   rather than leaving it implicit.

## Alternatives Considered

- **Coordinator imperatively loops over specialist agents itself** (calls
  each planned agent as a plain Python function, collects results) —
  simpler to write, but makes the Coordinator a second, competing
  execution engine parallel to LangGraph's own, defeating the reason
  LangGraph was chosen (ADR-0003: explicit, inspectable, checkpoint-able
  control flow). Rejected in favor of the Coordinator only ever writing a
  plan, with the graph's edges doing the actual execution.
- **A single global mutable agent/tool registry module-level dict** —
  simplest to write, but violates constitution §2's "avoid global state"
  rule directly and makes tests unable to isolate their own agent/tool
  registrations from each other. Rejected in favor of explicit,
  injectable `AgentRegistry`/`ToolRegistry` instances with a documented,
  cache-backed singleton accessor for production use.
- **Skip the workflow-engine-level retry/failure-recovery tier entirely**,
  relying only on `BaseAgent`'s internal catch-all — simpler, but leaves no
  safety net for a bug in the framework itself (as opposed to a documented
  agent failure mode), which constitution §9 explicitly requires a
  case-level fallback for. Rejected.

## Consequences

- **Positive:** adding a real specialist agent (Milestone M1+) requires
  implementing `BaseAgent.execute()`, declaring capabilities, registering
  it, and adding two lines to `investigation_graph.py` — no change to
  `WorkflowEngine`, `router.py`, `retry.py`, `failure_recovery.py`,
  `events.py`, or `metrics.py`. This was verified directly: the checked-in
  integration test registers fake, non-domain specialist agents and runs
  them through the real, compiled graph without touching any framework
  file.
- **Positive:** the parallel-fan-out correctness fix (point 5) means a
  future milestone with genuinely independent specialist agents (e.g. SOC
  Analyst and Threat Hunting Agents both consuming the same log evidence)
  can run concurrently in one LangGraph superstep safely, which was
  explicitly designed for even though no milestone requires it yet.
- **Negative:** the two-tier error-handling split (point 4) means a bug
  that manifests as an exception inside `BaseAgent.__call__` itself (not
  inside a concrete agent's `execute()`) is the only case where
  `workflow_engine.py`'s retry/failure-recovery actually activates — this
  is intentional (see point 4) but means that code path has less "natural"
  test coverage from real usage; the checked-in tests exercise it via a
  test double that overrides `__call__` directly to simulate this.
- **Negative:** `docs/dependency-rules.md`'s clarification (point 7) is a
  documentation fix landing in the same change as the code that needed it,
  rather than being decided before any code was written — flagged
  transparently here rather than silently patched, per constitution §12's
  "never edited to reverse a decision" spirit (this doesn't reverse
  anything; it makes an already-necessary exception explicit).
