# core/memory — Memory Layer

**Purpose:** The Memory Layer (`context/01_blueprint.md` §4, ADR-0006,
ADR-0010). Everything a case investigation or the future AI Analyst Chat
needs to remember, at four distinct scopes:

- **Session** (`session_memory.py`) — a per-process-session scratchpad
  (`ShortTermMemory`). Not the same as `CaseInvestigationState`
  (constitution §4.4: that's the *real* short-term memory an agent reads
  directly) — this is for session-scoped UI/API state outside a graph run.
- **Case** (`case_memory.py`) — analyst notes scoped to a case but outside
  graph-execution state (`CaseMemory`), persisted via `repository.py`.
- **Conversation** (`conversation_memory.py`) — case-scoped chat turn
  history for the AI Analyst Chat (blueprint §13), a new Protocol distinct
  from `CaseMemory` (see ADR-0010).
- **Long-term** (`long_term.py`, `vector_store.py`) — cross-case retrieval
  (`LongTermMemory`/`VectorMemory`), always advisory (ADR-0006): a backend
  outage degrades to "no historical context," never blocks an investigation.

Supporting infrastructure: `models.py` (typed contracts every store reads
and writes), `db_models.py`/`repository.py` (SQLite persistence for case
notes and long-term metadata, via `core.db.BaseRepository`), `lifecycle.py`
(TTL expiration/cleanup), `context_builder.py`/`context_serializer.py`
(assemble → filter → dedup → rank → truncate → render memory into an
LLM-ready or loggable shape), `metrics.py` (retrieval timing, hit/miss,
eviction counters), `registry.py`/`manager.py` (`MemoryRegistry` for named
backend lookup, `MemoryManager` as the single facade other layers depend
on).

**Responsibility:** Long-term memory is always advisory — a backend outage
degrades to "no historical context," never blocks an investigation (ADR-0006).

**Implemented:**
- `interfaces.py` — `ShortTermMemory`/`CaseMemory`/`LongTermMemory`/
  `VectorMemory` Protocols (unchanged from the Multi-Agent Framework
  milestone).
- `models.py`, `db_models.py`, `repository.py` — typed contracts + SQLite
  persistence.
- `session_memory.py`, `case_memory.py`, `conversation_memory.py`,
  `vector_store.py`, `long_term.py` — concrete implementations of every
  Protocol above.
- `lifecycle.py`, `context_builder.py`, `context_serializer.py`,
  `metrics.py`, `registry.py`, `manager.py` — supporting infrastructure.

**Not yet built, by explicit scope (ADR-0005/0006/0010):** the real ChromaDB
backend (`vector_store.py` currently ships `InMemoryVectorStore` — a
genuinely working but non-production reference implementation of the same
`VectorMemory` Protocol) and any populated knowledge/cybersecurity data.

**Why it exists:** This is what makes the Copilot smarter the longer it's
used, per the PDF's explicit Project 9 requirement — and what lets a future
Memory Agent do its job.

**Future expansion:** Swap `InMemoryVectorStore` for a ChromaDB-backed
implementation (M6, same `VectorMemory` Protocol — no caller changes);
multi-tenant memory partitioning if/when multi-org support is added.
