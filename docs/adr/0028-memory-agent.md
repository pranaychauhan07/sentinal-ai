# ADR-0028: Memory Agent (Graph-Integrated Cross-Case Retrieval)

**Status:** Accepted
**Date:** 2026-07-22

## Purpose

Blueprint §7 names a Memory Agent from day one: *"Cross-case learning — 'have
we seen this IP/pattern before?' ... embed new findings into ChromaDB,
retrieve similar past cases at investigation start, surface to Coordinator
... Failure handling: memory retrieval is always advisory/optional."*
ADR-0027 (the prior session) deliberately built every piece this agent needs
— a real `ChromaVectorStore`, semantic embedders, `LongTermMemoryManager`'s
case-scoped/cross-case/category-filtered retrieval, populated OWASP/
playbook/detection knowledge — but stopped short of the graph node itself,
recording in its own "Alternatives Considered" section: *"A graph-integrated
Memory Agent (automatic 'similar past cases' context at investigation start)
remains named future work, not silently dropped."* This ADR is that future
session. It closes the last named M6 intelligence component.

## Decision

Four decisions, made together, before any code was written.

### 1. Retrieval happens in `core/services/case_service.py` (async), never inside `MemoryAgent.execute()` (sync) — mirrors `MitreMappingAgent`'s "resolve pre-hydrated data" shape exactly

`core/agents/base.py`'s `BaseAgent.execute()` is a synchronous method;
`core/graph/workflow_engine.py` invokes every agent node synchronously, with
no event loop in scope. `LongTermMemoryManager`'s retrieval methods
(`find_similar_in_case`, `find_similar_excluding_case`, ...) are `async def`
— they call an embedder and a vector store, both potentially real I/O.
Bridging sync-to-async inside `BaseAgent`/`WorkflowEngine` to let an agent
`await` mid-execution would be a change to already-shipped, tested framework
code, forbidden by this task's "never redesign completed modules" instruction
and by constitution §10 ("the architecture is not renegotiated per
feature").

The existing, already-verified precedent is `MitreMappingAgent`/
`IncidentResponseAgent`/`ReportGeneratorAgent`: each reads a `*_records`
field `core/services/case_service.py` hydrates (synchronously, from
already-awaited async calls) *before* `engine.run(state)` is ever called, and
each agent's `execute()` only resolves/aggregates that already-fetched data
into a typed, case-level summary — never performing new I/O itself. The
Memory Agent follows the identical shape:

- A new async function, `_hydrate_memory_context_record` (module docstring,
  `case_service.py`), runs after IOC extraction and Finding generation (the
  point at which this case's most representative text — its Finding titles/
  descriptions, plus this upload's extracted IOC types — already exists),
  and calls `core.memory.investigation_context.build_investigation_memory_context`
  (new, `core/memory/`) for the five vector categories
  (`case_summary`/`finding`/`ioc`/`mitre_technique`/`report`) plus
  `core.knowledge.retrieval.KeywordKnowledgeRetriever` for related
  OWASP/playbook/detection-engineering reference documents.
- The combined result is reduced to a single plain
  `dict[str, object]` and hydrated onto a new
  `CaseInvestigationState.memory_context_record` field — single-writer,
  scalar, no concurrent-write reducer needed, exactly matching
  `incident_response_plan_record`'s existing precedent.
- `core/agents/memory_agent.py`'s `MemoryAgent.execute()` reads that dict,
  validates/reconstructs it into typed models via a new
  `core/tools/memory_tools.py` tool (`MemoryContextResolutionTool`), and
  writes a case-level `MemoryAgentResult` — it never calls
  `core.memory.manager`/`core.memory.long_term` itself.

This keeps constitution §4.4's rule ("Long-term memory is accessed *only*
through the Memory Agent — no specialist agent queries ChromaDB directly")
true in the sense that matters: no agent other than the one whose entire
purpose is memory retrieval ever sees or surfaces this data, and the
*mechanism* of retrieval — case_service.py performing the awaited I/O on the
Memory Agent's behalf — is the same mechanism already accepted for MITRE
mapping/incident response/report generation's cross-cutting data.

### 2. The deterministic "Memory Service" lives in `core/memory/investigation_context.py`, not `core/tools/`

`docs/dependency-rules.md` rule 5 explicitly **forbids** `core/tools` from
importing `core/memory` ("never `core/agents`, `core/graph`, or
`core/memory`") — unlike the rule 5/5b/5c exceptions already granted for
`core/knowledge`/`core/incident_response`/`core/reporting`, no such exception
exists for `core/memory`, and this ADR does not invent one: the retrieval
logic that actually calls `LongTermMemoryManager` (ranking is already done by
the vector store; this module's job is confidence-thresholding, per-category
top-K, and cross-category deduplication before the result ever reaches a
tool or agent) stays inside `core/memory` itself, as a new sibling module to
`long_term.py`/`manager.py` — genuinely reusable outside the Memory Agent too
(a future on-demand "similar cases" API route could call it directly).
`core/tools/memory_tools.py` therefore stays dict/primitive-shaped, exactly
like `vuln_tools.py`/`owasp_tools.py` — it defines its own local Pydantic
input models (`RawSimilarItem`, `RawKnowledgeItem`, ...) rather than
importing `core.memory.interfaces.SimilarResult`, so no new cross-leaf import
edge is needed at all.

`core/services/case_service.py` gains one more documented rule-4d exception:
`core.memory.investigation_context` (mirroring the existing
`core.memory.{case_memory, repository, long_term, manager}` grant) and, new,
`core.knowledge.{registry, retrieval, models}` — worded identically to rule
4j's already-established grant of the same three modules to
`conversation_service.py` for the same reason (read-only Knowledge Layer
search, never a new business decision).

### 3. `SimilarResult` gains a `recorded_at` timestamp — additive, backward-compatible

The task's explicit "every item must include ... Timestamp" requirement has
no existing field to read: `LongTermMemoryManager.record`'s stored metadata
(`case_id`, `finding_id`, `excerpt`, `category`) never included one.
Extended, not redesigned, exactly like ADR-0027 added `category` the same
way: `record()` now also stores `recorded_at` (ISO-8601, UTC); `SimilarResult`
gains `recorded_at: datetime | None = None` (defaults to `None` for any
vector written before this change, so no backfill/migration is required);
`ChromaVectorStore`/`InMemoryVectorStore` parse it back out defensively (a
missing or malformed value degrades to `None`, never raises). No other field
on `SimilarResult`, `VectorMemory`, or `LongTermMemory` changes.

### 4. Cross-cutting, not evidence-type-gated; "malware family"/"threat actor" are not new structured fields

`memory_retrieval` is appended to *every* evidence type's required
capabilities in `_required_capabilities_for`, identically to
`mitre_technique_mapping`/`incident_response_synthesis`/`report_generation` —
retrieval is meaningful (even if it returns nothing) for every case
regardless of evidence type, and blueprint §9 places "Memory Agent (read)"
immediately after evidence classification, before the Coordinator, i.e.
logically the *first* cross-cutting step — reflected here by `MemoryAgent`
running in the same parallel entry-step fan-out as every other cross-cutting
agent (the graph has no sequential-phase concept to place it "before" SOC
Analyst in; see ADR-0023's "Alternatives Considered" for why teaching the
graph dependency-ordered waves is out of scope).

The task brief names "similar malware families" and "previously seen threat
actors" among the Memory Agent's responsibilities. This codebase has no
`MalwareFamily`/`ThreatActor` model, category, or knowledge source anywhere
— inventing one with no backing data would be exactly the kind of
fabrication constitution §1.9/§10 forbids ("never hallucinate unavailable
data"). Matching ADR-0027's own precedent (`THREAT_INTELLIGENCE`/
`INVESTIGATION_TEMPLATE` knowledge sources named but explicitly left
unpopulated), this ADR does not add a structured field for either: free-text
finding/report excerpts already indexed under the `finding`/`report`
categories may incidentally mention a malware or actor name, and remain
retrievable through `similar_findings`/`similar_reports`, but `MemoryContext`
has no `similar_malware_families`/`known_threat_actors` field pretending to
be a dedicated, curated capability that does not exist. Named explicitly in
"Remaining Work," not silently dropped.

## Alternatives Considered

- **Bridge `BaseAgent`/`WorkflowEngine` to support an async `execute()`.**
  Rejected: a framework change to already-shipped, tested code, forbidden by
  this task's explicit "never redesign completed modules" instruction and by
  constitution §10.
- **Have `MemoryAgent` construct its own `LongTermMemoryManager` and call it
  synchronously via `asyncio.run()` inside `execute()`.** Rejected: this
  either creates a new event loop per agent invocation (wasteful, and unsafe
  if ever called from inside an already-running loop — `case_service.py`'s
  own async context) or silently relies on no caller ever running the graph
  from within an event loop, an assumption nothing in this codebase
  guarantees. The pre-hydration pattern has zero such risk and is the
  already-accepted precedent.
- **Put the ranking/threshold/dedup Memory Service inside
  `core/tools/memory_tools.py`, granting it a new `core/memory` import
  exception (a "rule 5d").** Rejected in favor of keeping it in `core/memory`
  itself: the logic is pure vector-memory aggregation with no tool-specific
  concern, it is independently reusable (a future on-demand API route),
  and it avoids adding a new leaf-to-leaf dependency edge rule 5 does not
  already contemplate.
- **Fabricate `SimilarMalwareFamily`/`SimilarThreatActor` models populated
  from keyword-matching finding excerpts.** Rejected: no genuine detection
  logic backs "this excerpt names a malware family" or "this excerpt names a
  threat actor" anywhere in this codebase; a field that looks authoritative
  but is really a regex guess is worse than not having the field, per
  constitution's "never hallucinate" principle applied to structured output
  the same way it already applies to LLM freeform text.

## Consequences

**Easier:** Every future case investigation surfaces "have we seen this
before?" context automatically, with no analyst action required — the
Investigation Trail (`state.thoughts`) now carries a `MemoryAgent` entry
alongside every other specialist's reasoning; a future Report Generator
Agent section or `apps/web` "Similar Cases" panel can read
`agent_outputs["memory_agent"]` directly, the same way every other
cross-cutting agent's output is already consumed.

**Harder / foreclosed:** Memory context is always one step "as fresh as this
upload's already-generated Findings" — it reflects the case's Finding
titles/descriptions and this upload's IOC types as the query signal, not a
richer NLP summary of the raw evidence content (building one would duplicate
`SocFinding`/`ThreatHuntingReport` generation, not memory retrieval). A case
with zero findings yet (a parser producing no IOCs, or an evidence type with
no capability match) queries with a thin fallback signal (evidence source/
type) and can legitimately retrieve nothing — a documented "insufficient
signal" degraded outcome, not an error, mirroring `MitreMappingAgent`'s
"unmapped" precedent.

**Named future work, not built here:** a dedicated `similar_malware_families`/
`known_threat_actors` capability (would require a new knowledge/detection
model this codebase doesn't have); an on-demand `apps/web`/API "Similar
Cases" panel consuming `MemoryAgentResult` directly (today it is only
visible via `AgentExecutionResult`/the Investigation Trail); teaching
`core/graph` genuine dependency-ordered waves so a future Memory Agent could
literally run *before* other specialists in the same graph invocation instead
of using the pre-hydration workaround (ADR-0023's identical, still-open
alternative).

**Never touched:** `core/graph/workflow_engine.py`, `core/graph/routing.py`,
`core/agents/planning_agent.py`, `core/agents/coordinator.py`, every prior
specialist agent/framework, `core/memory/{long_term,manager,context_builder,
conversation_memory,case_memory,chroma_vector_store,vector_store}.py`'s
existing methods/behavior (only additive fields), and
`core/services/conversation_service.py` (unrelated to this session) —
extended (an eleventh specialist agent, an eleventh capability, one more
`*_record`-shaped hydration function, one new `core/memory` leaf module, one
new dict-shaped tool) but never redesigned.
