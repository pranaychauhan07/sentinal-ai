# ADR-0010: Memory & Knowledge Layer Shape

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

ADR-0006 scoped "memory" to two mechanisms: the LangGraph state itself
(short-term) and a future ChromaDB-backed store (long-term, M6). That framing
is still correct as far as it goes, but it left several concepts blueprint §7
and §13 already require homes for, with no ADR covering them: per-case notes
that outlive one graph run but aren't cross-case learning (`CaseMemory`,
already a Protocol with no implementation), the AI Analyst Chat's
conversation history, a context-assembly step that turns raw
`CaseInvestigationState` + retrieved memory into a bounded prompt, and the
Knowledge Layer (MITRE/OWASP/etc.) that blueprint §4 places as its own layer
but that no ADR or code has scoped yet. Building the reusable infrastructure
for all of this before any concrete cybersecurity agent exists (mirroring
ADR-0009's "framework first" precedent for the Multi-Agent Framework) is this
ADR's subject.

## Decision

Extend, not replace, ADR-0006/0005's two-mechanism split:

- **`core/memory`** gains concrete implementations of the existing
  `ShortTermMemory`/`CaseMemory`/`LongTermMemory`/`VectorMemory` Protocols
  (`session_memory.py`, `case_memory.py`, `long_term.py`, `vector_store.py`),
  a new `ConversationMemory` Protocol + implementation for chat history, a
  `MemoryRecord`/`MemoryQuery` typed contract layer (`models.py`) every
  concrete store operates on, SQLite persistence for case notes and
  long-term metadata via `core.db.BaseRepository` (no new architecture — the
  same repository pattern `core/db` already established), a lifecycle
  manager for TTL-based expiration/cleanup, a context builder + serializer
  that assemble/filter/rank/dedupe/budget memory into what an agent or the
  future AI Analyst Chat actually sends an LLM, and a `MemoryManager` facade
  wiring all of the above — the single object a future Memory Agent
  constructs against, the same role `AgentRegistry`/`ToolRegistry` play for
  their layers.
- **ChromaDB itself remains exactly where ADR-0005 put it** — M6, not built
  here. `vector_store.py` ships a real (not fake) in-memory cosine-similarity
  `VectorMemory` implementation so the rest of the layer (long-term memory,
  context building) is genuinely testable and usable today, with Chroma as a
  drop-in swap later (same Protocol, per ADR-0005's "swappability" goal).
- **`core/knowledge`** gains `KnowledgeSource`/`KnowledgeRetriever` Protocols,
  a `KnowledgeSourceRegistry`, and one concrete, deterministic
  `KeywordKnowledgeRetriever` — explicitly with **no MITRE/OWASP/threat-intel
  data populated**, per this task's scope. Populating real knowledge sources
  is cybersecurity-domain work for a later milestone (M2+); this ADR only
  gives that future work a typed home so it doesn't invent its own shape
  ad hoc.

## Alternatives Considered

- **Wait until a concrete Memory Agent needs these pieces, build them then**
  — rejected for the same reason ADR-0009 rejected waiting on the
  Multi-Agent Framework: retrofitting persistence/context-assembly seams
  into already-written specialist agents is more invasive than giving every
  future agent a stable interface from the start.
- **Fold conversation history into `CaseMemory`** — rejected; a case's
  analyst notes and a chat session's turn history have different lifecycles
  (notes persist with the case indefinitely, chat history is
  windowed/trimmed for token budget) and different consumers. Conflating
  them would force one Protocol to serve two shapes, violating Principle 3
  (small, focused modules).
- **Build a real embedding-backed vector store now instead of ChromaDB**
  — rejected; ADR-0005's reasoning (self-hostable, independent availability,
  advisory-only failure mode) still applies unchanged. The in-memory store
  here is a *reference implementation of the Protocol* for testability, not
  an attempt to preempt that decision.
- **Populate MITRE/OWASP knowledge now since the folders already exist**
  — explicitly rejected per this task's scope: this ADR is infrastructure,
  cybersecurity intelligence is separate, later work.

## Consequences

- **Positive:** every future specialist agent (M1+) gets working session,
  case, conversation, and (advisory) long-term memory, plus a knowledge-base
  seam, without inventing any of it ad hoc when the first real agent is
  built. `core/agents/base.py`'s existing `case_memory: CaseMemory | None`
  constructor parameter is satisfied by a real implementation for the first
  time, with zero changes to `BaseAgent` itself.
- **Negative:** the in-memory vector store and keyword retriever are
  genuinely usable but not what ships in production (Chroma, and populated
  knowledge data, still need to land later) — a reviewer must not mistake
  "the Protocol is implemented" for "the production backend is implemented."
  Documented explicitly in both modules' docstrings and READMEs to prevent
  that confusion.
