# ADR-0027: Production Memory, Embedding, Chat-Provider & Knowledge Infrastructure

**Status:** Accepted
**Date:** 2026-07-22

## Purpose

`docs/roadmap.md`'s M6 entry lists four remaining items after the Memory &
Knowledge Layer *framework* (ADR-0010) and the AI Analyst Chat *pipeline*
(ADR-0025) shipped: a real ChromaDB backend, populated MITRE/OWASP knowledge, a
real LLM-backed `ChatModelProvider`, and the `apps/web` Threat Timeline/AI
Analyst Chat UI. This session closes the first three — the task explicitly
excludes frontend work, so the fourth is untouched.

Every placeholder this session replaces was deliberately, explicitly scoped as
"not this milestone" by an earlier ADR:

- ADR-0010: *"ChromaDB itself remains exactly where ADR-0005 put it — M6, not
  built here."* / *"`core/knowledge` gains ... explicitly with no MITRE/OWASP/
  threat-intel data populated."*
- ADR-0025: *"No OpenAI/Gemini/Ollama client is implemented this session — this
  is the structural guarantee behind 'never hallucinate unavailable data.'"* /
  *"deterministic keyword-overlap relevance scoring (not semantic/embedding
  search — a documented scope boundary for a future upgrade behind the same
  `RetrievedItem` shape)."*

Nothing here reverses those decisions; this ADR is the promised follow-up each
one pointed to.

## Decision

### 1. ChromaDB as the concrete `VectorMemory` backend — Protocol extended, not replaced

`core/memory/interfaces.py`'s `VectorMemory` Protocol (two methods:
`upsert_embedding`, `query_embedding`) is extended with `upsert_embeddings_batch`,
`delete`, `delete_case`, and optional `case_id`/`metadata_filter` kwargs on
`query_embedding` — all additive, backward-compatible (existing callers of the
two-arg form are unaffected). This is a genuine extension, not a redesign: the
task's own bar ("production-ready... support persistent collections, similarity
search, metadata filtering, case-scoped retrieval, cross-case retrieval,
deletion, updates, batch insertion") is broader than the original two-method
sketch, and the original Protocol was never claimed to be final — ADR-0010
called `InMemoryVectorStore` "a reference implementation... for testability,"
not the frozen contract shape.

`core/memory/chroma_vector_store.py` implements the extended Protocol via
`chromadb.PersistentClient(path=Settings.chroma_persist_dir)`, one collection
(`case_findings_embeddings`, blueprint §8's exact name), using Chroma's native
`where` metadata filtering for case-scoped vs. cross-case queries. Per
`docs/dependency-rules.md` rule 6, this remains the only new module importing
`chromadb` directly. `InMemoryVectorStore`/`NullVectorStore`
(`core/memory/vector_store.py`) are updated to satisfy the same extended
Protocol — they stay genuinely useful test/dev references, per ADR-0010's
original intent, not deprecated.

### 2. A provider-agnostic `EmbeddingProvider` abstraction, mirroring `ChatModelProvider`

`core/memory/vector_store.py`'s existing `TextEmbedder` Protocol (one method:
`embed`) is reused unchanged. `core/memory/embedding_providers.py` adds three
concrete implementations (`OpenAIEmbeddingProvider`, `GeminiEmbeddingProvider`,
`OllamaEmbeddingProvider`), each a thin wrapper over an already-vendored
`langchain-*` client (`langchain_openai.OpenAIEmbeddings`,
`langchain_google_genai.GoogleGenerativeAIEmbeddings`,
`langchain_community.embeddings.OllamaEmbeddings` — zero new dependencies), and
a `build_text_embedder(settings)` factory selecting by `Settings.llm_provider`.
Per constitution §7 ("fail gracefully") and ADR-0006's "memory is always
advisory" contract, a missing API key or a provider call failure never raises
out of the factory or out of `LongTermMemoryManager` — it degrades to
`HashingTextEmbedder` (construction time) or an empty result (call time),
logged, never silently.

### 3. Concrete `ChatModelProvider` backends, same graceful-fallback shape

`core/conversation/llm_provider.py` gains `OpenAIChatModelProvider`,
`GeminiChatModelProvider`, `OllamaChatModelProvider` (same `langchain-*`
wrapping pattern) and `build_chat_model_provider(settings)`. Every concrete
provider is invoked only with the fully-assembled, already-grounded
`PromptPayload` `PromptBuilder` produces — the system instructions still say
"answer only from the provided context, cite sources, say so if the context is
insufficient" regardless of which backend answers, so ADR-0025's anti-
hallucination guarantee is a property of the *prompt*, not of
`TemplateChatModelProvider`'s specific non-generative implementation.
`TemplateChatModelProvider` remains the default, always-available fallback
(unconfigured provider, or a real provider's call raising `ChatProviderError`)
— `ResponseOrchestrator.orchestrate` is extended to catch that failure and
retry with the template provider for the same request rather than crashing the
pipeline (constitution §9, "External API failures... converted to a degraded
result").

### 4. Knowledge population fills already-reserved, empty enum slots

`core.knowledge.models.KnowledgeSourceType` already names `OWASP_TOP10`,
`SECURITY_PLAYBOOK`, `DETECTION_RULE`, `THREAT_INTELLIGENCE`,
`INVESTIGATION_TEMPLATE` (ADR-0010) — only `MITRE_ATTACK` had a concrete
source. Three new leaf subpackages (`core/knowledge/owasp/`,
`core/knowledge/playbooks/`, `core/knowledge/detection/`), each mirroring
`core/knowledge/mitre/`'s exact shape (typed models → offline-vendored data
file under `data/knowledge/` → loader → `KnowledgeSource` implementation),
fill `OWASP_TOP10`, `SECURITY_PLAYBOOK` (covers both "security best practices"
and "incident response guidance" — both are general reference/playbook
content, not case-specific findings), and `DETECTION_RULE`. `THREAT_INTELLIGENCE`
and `INVESTIGATION_TEMPLATE` remain unpopulated — out of this task's four named
content areas (OWASP, best practices, IR guidance, detection engineering).
`core/knowledge/bootstrap.py` registers MITRE (via the existing, **completely
unmodified** `core.knowledge.mitre.{bootstrap,source}`) plus the three new
sources into one `KnowledgeSourceRegistry`, called once at `apps/api/main.py`
startup.

**This is read-only reference content, never the case-specific MITRE mapping
engine** (`core/findings/mapping_rules.py`, `core/knowledge/mitre/lookup.py`) —
neither is touched. The new Knowledge Layer sources answer "what does OWASP say
about broken access control," not "does this case's evidence map to T1110";
those stay two structurally independent systems, per this task's explicit
instruction.

### 5. Conversation retrieval gains two new categories, not a new pipeline

`core.conversation.models.EvidenceCategory` gains `KNOWLEDGE` and
`SIMILAR_CASE` (alongside the existing `FINDING`/`IOC`/`MITRE_MAPPING`/
`REPORT`/`TIMELINE_EVENT`). `RetrievalLayer`'s existing one-table-per-category
dispatch (`_CATEGORY_EXTRACTORS`) gets two more rows; `ToolSelectionEngine`
gets two more keyword groups. `core/services/conversation_service.py`
additionally queries the Knowledge Layer (`KeywordKnowledgeRetriever`,
synchronous, already-built) and `LongTermMemoryManager.find_similar_excluding_case`
(the new cross-case method) when those categories are selected — both
advisory, both empty-on-failure, matching every other retrieval path's
existing contract. `ConversationContextBuilder` gains a dedup step (drop
items whose normalized text duplicates an already-ranked item's) before
ranking — a real, previously-unhandled gap once a second retrieval source can
plausibly surface overlapping text.

### 6. Long-term memory gets a write path — closing blueprint §9 step 11

Nothing wrote to `LongTermMemoryManager` before this session (ADR-0010 built
the store; no caller existed). `core/services/case_service.py` gains a step,
after a case investigation persists its Report, that calls
`LongTermMemoryManager.record(...)` for the case's findings/report summary,
tagged by a new `category` field in vector metadata (`finding`/`ioc`/
`mitre_technique`/`report`/`case_summary`). This directly satisfies blueprint
§9's data-flow step 11 ("Memory Agent (write) — embeds this case's findings
into ChromaDB for future retrieval") without a new `core/agents/memory_agent.py`
or any `core/graph`/`CaseInvestigationState` change (see "Alternatives
Considered").

This adds one new, narrowly-scoped `docs/dependency-rules.md` edge:
`core/services/case_service.py`'s existing rule-4d exception (`core.memory.
{case_memory, repository}`) is extended to `core.memory.{case_memory,
repository, long_term, manager}`. `core/services/conversation_service.py`'s
existing rule-4j exception is extended to include `core.knowledge.{registry,
retrieval}` for the same reason. Both extensions are additive to already-
granted modules in the same package family, not a new kind of exception.

## Alternatives Considered

- **A new `core/agents/memory_agent.py` graph node**, matching blueprint §7's
  literal Memory Agent description (read at investigation start, write at
  investigation end, both as graph steps). Rejected for this session: it would
  require a new `CaseInvestigationState` field and graph wiring change — real
  surface area on an already-completed, tested module (`core/graph`) — for a
  capability this task scoped as "make chat + memory production-ready," not
  "wire a new pipeline stage." The write path lands in `case_service.py`
  (mirroring how `ReportGeneratorAgent`'s report and `IncidentResponsePlan`
  already get service-level persistence hooks alongside their graph-node
  agents); the read path is exposed through `core/memory` and surfaced to the
  one consumer that currently needs it, the AI Analyst Chat. Building a full
  graph-integrated Memory Agent (advisory context attached to
  `CaseInvestigationState` before the Coordinator runs) is named explicitly as
  future work below, not silently dropped.
- **Reusing `HashingTextEmbedder`'s dimensionality contract for real
  embeddings.** Rejected — real embedding models return provider-specific
  dimensions (1536 for `text-embedding-3-small`, different again for
  Ollama/Gemini models); `ChromaVectorStore` stores whatever dimension a given
  embedder returns per-collection, consistent with how Chroma itself works,
  rather than forcing a fixed 64-dim contract onto real embeddings.
- **A single mega "AI provider" class covering chat + embeddings.** Rejected —
  `ChatModelProvider` and `TextEmbedder` are different operations with
  different call shapes and different consumers (`core/conversation` vs.
  `core/memory`); constitution §1.3/§1.4 (small, focused modules; one
  responsibility per module) argues for keeping them as two Protocols, matching
  the precedent `ChatModelProvider` already set as its own single-method seam.

## Consequences

**Positive:** the AI Analyst Chat can now answer with a real LLM's synthesis
(when configured) while keeping the exact same anti-hallucination structural
guarantee; long-term memory is genuinely written and queryable across cases for
the first time; the Knowledge Layer's four reserved-but-empty enum slots are no
longer silently unimplemented seams — three of them now serve real read-only
reference content the chat can cite.

**Negative / disclosed limitations:**
- No graph-integrated Memory Agent yet — a new case's Coordinator/Planning
  stage still does not see "similar past cases" as automatic context; that
  requires the graph-node work explicitly deferred above.
- `THREAT_INTELLIGENCE` and `INVESTIGATION_TEMPLATE` knowledge sources remain
  unpopulated — out of this task's four named content areas.
- Real embedding/chat providers require live network calls; every failure mode
  (missing key, unreachable Ollama host, rate limit) has a documented, tested
  fallback, but latency/cost characteristics are now a real operational
  concern this project didn't have when everything was deterministic — flagged
  in `core/memory/README.md`/`core/conversation/README.md`, not hidden.
- `apps/web`'s AI Analyst Chat / Threat Timeline pages remain unbuilt, per this
  task's explicit exclusion.

## Future Expansion

- A graph-integrated Memory Agent (blueprint §7) attaching "similar past case"
  context to `CaseInvestigationState` before the Coordinator runs.
- `THREAT_INTELLIGENCE`/`INVESTIGATION_TEMPLATE` knowledge sources.
- Streaming chat responses; a persisted export/embedding cache to avoid
  re-embedding identical finding text across repeated case runs.
