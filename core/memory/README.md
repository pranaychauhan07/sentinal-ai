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
eviction counters, plus ADR-0027's embedding-call/vector-store-call
timing), `registry.py`/`manager.py` (`MemoryRegistry` for named backend
lookup, `MemoryManager` as the single facade other layers depend on),
`embedding_providers.py`/`chroma_vector_store.py`/`exceptions.py`
(ADR-0027's real production backend).

**Responsibility:** Long-term memory is always advisory — a backend outage
degrades to "no historical context," never blocks an investigation (ADR-0006).

**Implemented:**
- `interfaces.py` — `ShortTermMemory`/`CaseMemory`/`LongTermMemory`/
  `VectorMemory` Protocols. ADR-0027 extends `VectorMemory` (batch upsert,
  delete, case-scoped/metadata-filtered query — the "production-ready"
  bar) and `LongTermMemory` (category-tagged `record`, case-scoped and
  cross-case-excluding retrieval).
- `models.py`, `db_models.py`, `repository.py` — typed contracts + SQLite
  persistence.
- `session_memory.py`, `case_memory.py`, `conversation_memory.py`,
  `vector_store.py`, `long_term.py` — concrete implementations of every
  Protocol above. `vector_store.py`'s `InMemoryVectorStore`/
  `NullVectorStore` remain genuinely useful test/dev references, now
  satisfying the extended Protocol too.
- `chroma_vector_store.py` (ADR-0027) — `ChromaVectorStore`, the real,
  persistent production `VectorMemory` backend (local `chromadb.
  PersistentClient`, cosine similarity, collection
  `case_findings_embeddings` per blueprint §8). The only module (per
  docs/dependency-rules.md rule 6) that imports a vector-store client.
- `embedding_providers.py` (ADR-0027) — `OpenAIEmbeddingProvider`/
  `GeminiEmbeddingProvider`/`OllamaEmbeddingProvider` (real semantic
  embeddings via already-vendored `langchain-*` clients) +
  `build_text_embedder`, selecting among them (or `HashingTextEmbedder`,
  when unconfigured/unreachable) per `Settings.llm_provider`.
- `exceptions.py` (ADR-0027) — `InvalidEmbeddingError`/
  `EmbeddingProviderError`/`VectorStoreError`.
- `lifecycle.py`, `context_builder.py`, `context_serializer.py`,
  `metrics.py`, `registry.py`, `manager.py` — supporting infrastructure.
  `manager.py` gained `build_long_term_memory`/`default_long_term_memory`
  (ADR-0027): the one place "real ChromaDB + real embedder" vs. "degraded
  Null/Hashing fallback" is decided.
- `investigation_context.py` (ADR-0028) — `build_investigation_memory_context`,
  the graph-integrated Memory Agent's "Memory Service": per-category
  ranking, confidence-thresholding, top-K truncation, and cross-call
  deduplication over `LongTermMemoryManager`'s retrieval, called by
  `core/services/case_service.py` (never by `core/tools`, which
  `docs/dependency-rules.md` rule 5 forbids from importing `core/memory`).
- `interfaces.py`'s `SimilarResult` gained `recorded_at` (ADR-0028) —
  `LongTermMemoryManager.record` now stamps a timestamp into every vector's
  metadata; `None` for any vector recorded before this field existed.

**Graph-integrated Memory Agent: built (ADR-0028).**
`core.agents.memory_agent.MemoryAgent` is a real, cross-cutting graph node
(`core/graph/investigation_graph.py`) that runs on every investigation,
surfacing "similar past cases" automatically — blueprint §7's exact
requirement. It never imports or queries this package directly at execution
time (`BaseAgent.execute()` is synchronous; this package's retrieval methods
are `async def`): `core/services/case_service.py`'s
`_hydrate_memory_context_record` calls `investigation_context.
build_investigation_memory_context` (awaited, before the graph runs) and
hydrates the result onto `CaseInvestigationState.memory_context_record` for
the agent to resolve. See `docs/adr/0028-memory-agent.md` for the full
sync/async reasoning.

**Why it exists:** This is what makes the Copilot smarter the longer it's
used, per the PDF's explicit Project 9 requirement. Case investigations
write real findings/report summaries into long-term memory
(`core/services/case_service.py`), the AI Analyst Chat reads them back
across cases (`core/services/conversation_service.py`), and every new
investigation's Memory Agent reads them back automatically (ADR-0028).

**Future expansion:** multi-tenant memory partitioning if/when multi-org
support is added; a persisted embedding cache to avoid re-embedding
identical finding text across repeated case runs; a dedicated
malware-family/threat-actor knowledge category (no such model exists in this
codebase yet — see ADR-0028's "Alternatives Considered").
