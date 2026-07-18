# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Still nothing cybersecurity-related exists — no domain models, no parsers, no concrete specialist agent.** What is now complete, beyond the M0 engineering foundation and the M3 Multi-Agent Framework, is the **Memory & Knowledge Layer**: the reusable memory/context/knowledge infrastructure every future specialist agent and the future Memory Agent will be built on top of. Built ahead of the milestone schedule (normally M6) at explicit user direction — framework-first, before any domain-specific agent exists, mirroring the precedent set by the Multi-Agent Framework session. Full design rationale: `docs/adr/0010-memory-knowledge-layer-shape.md`.

### M0 foundation + Multi-Agent Framework (unchanged from prior session)

- **Configuration, logging, shared contracts, DB foundation, FastAPI app, governance** — unchanged, see prior session detail in git history / `docs/adr/0001-0009`.
- **`core/agents/`, `core/tools/`, `core/graph/`** — `BaseAgent`/`BaseTool`, `AgentRegistry`/`ToolRegistry`, `CoordinatorAgent`/`PlanningAgent`, `WorkflowEngine` (real compiled LangGraph `StateGraph`), `routing.py`, `events.py`/`retry.py`/`failure_recovery.py`/`metrics.py`/`execution_context.py`. 158 tests as of the prior session.

### Memory & Knowledge Layer (new this session)

- **`core/memory/models.py`** — `MemoryScope` (SESSION/CASE/CONVERSATION/LONG_TERM), `MemoryPriority`, `MemoryRecord` (frozen, with `is_expired()`), `MemoryQuery`, `MemoryQueryResult`, `ConversationRole`/`ConversationTurn`.
- **`core/memory/db_models.py` + `repository.py`** — `MemoryRecordRow` (SQLAlchemy `Entity` subclass, indexed on `(scope, case_id)`) and `MemoryRepository` (subclasses `core.db.BaseRepository`; adds `save` (merge-upsert), `find` (scope/case/text/tag filtering), `delete_expired`, `get_record`). This is the layer's only Pydantic↔ORM translation point (constitution §7).
- **Concrete implementations of every memory Protocol** (`core/memory/interfaces.py`'s Protocols were previously abstraction-only; this session gave each a real backing):
  - `session_memory.py` — `SessionMemory` (`ShortTermMemory`): in-process per-session dict.
  - `case_memory.py` — `SQLiteCaseMemory` (`CaseMemory`): persisted case notes via `MemoryRepository`. **This is the first real value `BaseAgent`'s existing `case_memory: CaseMemory | None` constructor parameter can be given** — no change to `BaseAgent` itself.
  - `conversation_memory.py` — new `ConversationMemory` Protocol + `InMemoryConversationMemory`: case-scoped chat turn history for the future AI Analyst Chat (blueprint §13), bounded by `max_turns_per_case`.
  - `vector_store.py` — `InMemoryVectorStore` (`VectorMemory`): a genuinely working, brute-force O(n) cosine-similarity store — not a stub. `NullVectorStore`: documented no-op fallback. `HashingTextEmbedder` (`TextEmbedder` Protocol): deterministic feature-hashing embedder (uses `hashlib`, not the salted builtin `hash()`, so results are stable across process restarts) — exercises the vector store end-to-end with zero LLM-provider dependency. ChromaDB itself remains unbuilt, exactly as ADR-0005/0006 scoped it for Milestone M6.
  - `long_term.py` — `LongTermMemoryManager` (`LongTermMemory`): wraps an injected `VectorMemory` + `TextEmbedder`; every method catches backend failures and degrades to empty/no-op rather than raising (ADR-0006's "always advisory" contract enforced here, not just documented).
- **`core/memory/lifecycle.py`** — `MemoryLifecycleManager`: per-`MemoryScope` default TTLs (`DEFAULT_RETENTION`), `cleanup_expired()` (the reusable unit a future scheduled job calls), `default_expiry_for()`.
- **`core/memory/context_builder.py` + `context_serializer.py`** — `ContextBuilder`: `filter_active` → `deduplicate` → `rank` (priority, then recency) → `truncate_to_budget` (character-budget proxy for a token budget) → `assemble()` (`AssembledContext`). `ContextSerializer`: `to_prompt_text()` / `to_dict()`.
- **`core/memory/metrics.py`** — `MemoryMetricsCollector`: hit/miss/write/eviction counters, `time_retrieval()` context manager for timing. Deliberately self-contained (no `core.graph.events.EventBus` dependency — `core/memory` is a leaf layer that must never import `core/graph`).
- **`core/memory/registry.py` + `manager.py`** — `MemoryRegistry[BackendT]` (generic named-backend lookup, mirroring `AgentRegistry`/`ToolRegistry`'s pattern) + `default_memory_registry()`. `MemoryManager`: the single facade wiring session/case/conversation/long-term memory + context builder + serializer + metrics; every dependency optional and injected, degrading to advisory no-ops (never raising) when a piece isn't configured.
- **`core/knowledge/`** (previously empty, README-only):
  - `models.py` — `KnowledgeSourceType` (MITRE_ATTACK/OWASP_TOP10/THREAT_INTELLIGENCE/SECURITY_PLAYBOOK/DETECTION_RULE/INVESTIGATION_TEMPLATE — **no data populated**), `KnowledgeDocument`, `KnowledgeQuery`, `KnowledgeSearchResult`.
  - `interfaces.py` — `KnowledgeSource`/`KnowledgeRetriever` Protocols (abstraction only).
  - `registry.py` — `KnowledgeSourceRegistry` + `default_knowledge_registry()`, empty until a concrete source registers itself (a later milestone).
  - `retrieval.py` — `KeywordKnowledgeRetriever`: deterministic keyword/substring scoring across every registered source (constitution Principle 9) — explicitly not semantic/RAG retrieval; that's a documented future swap behind the same `KnowledgeRetriever` Protocol.
- **Testing** — 70 new tests (228 total, up from 158): every new module has a dedicated `tests/unit/test_*.py` file, including SQLite-persistence tests (`test_memory_repository.py`, `test_memory_case_memory.py`, `test_memory_lifecycle.py`, `test_memory_manager.py`) following `tests/unit/test_base_repository.py`'s real-SQLite-via-`test_settings`-fixture pattern, Protocol-conformance tests for every new concrete implementation, and advisory-degradation tests (a failing fake `VectorMemory` proving `LongTermMemoryManager`/`MemoryManager` never raise). mypy (strict on `core/`), `ruff check`, `ruff format`, and `scripts/check_dependency_rules.py` all pass; manual `grep` across `core/memory` and `core/knowledge` confirms no import of `core/agents`/`core/graph` (the two layers dependency rules forbid a leaf from calling up to).

**Explicitly NOT built, by this milestone's stated scope:** any domain DB model (`Case`/`Evidence`/`Finding`/etc.), any parser, any concrete specialist agent, any tool implementation, `core/security/*`, `core/reporting/*`, any `apps/web` code, any `/api/v1` domain route, the real ChromaDB backend (M6's actual production vector store — `InMemoryVectorStore` is a working reference implementation of the same Protocol, not a replacement for it), and any populated MITRE/OWASP/threat-intel/playbook/detection-rule/investigation-template knowledge data.

---

## Repository Status

```
apps/
  api/            FastAPI app (unchanged)                          [implemented]
  web/             Streamlit frontend                               [README only]
core/
  config/         (unchanged)                                       [implemented]
  logging/        (unchanged)                                       [implemented]
  exceptions.py, schemas.py, interfaces.py                          [implemented]
  agents/         (unchanged — framework only)                      [implemented — framework only]
  tools/          (unchanged — framework only)                      [implemented — framework only]
  memory/         interfaces.py (unchanged Protocols) + models.py,
                   db_models.py, repository.py, session_memory.py,
                   case_memory.py, conversation_memory.py,
                   vector_store.py, long_term.py, lifecycle.py,
                   context_builder.py, context_serializer.py,
                   metrics.py, registry.py, manager.py               [implemented — memory layer]
  knowledge/      models.py, interfaces.py, registry.py, retrieval.py
                   (no data populated)                               [implemented — abstraction + one deterministic retriever]
  graph/          (unchanged — framework only)                       [implemented — framework only]
  db/             (unchanged, no domain models)                      [implemented, no domain models]
  parsers/        (empty — README only)                              [not started]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       (empty — README only)                              [not started]
data/             (unchanged)
tests/
  unit/           44 test modules (228 tests)
  integration/    4 test modules (17 tests, including
                   test_investigation_graph.py — real compiled StateGraph)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (11 ADR files incl. template)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          (unchanged)
.github/          (unchanged)
```

186 files committed as of `eae4fb8` (the M0 + Multi-Agent Framework commit); this session added roughly 35 more (18 `core/` modules, 17 test files, 1 ADR) plus edits to 5 existing files, all currently uncommitted (see "Current Git Status" below). Root config/governance files unchanged and current, except `docs/roadmap.md` (M6 note added) and `CHANGELOG.md`, both updated this session.

**Naming note carried forward:** `context/02_repository.md` and `context/03_constitution.md` still do not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`. A prompt this session again referenced both non-existent filenames — flagged and worked around identically to prior sessions' notes.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0005/ADR-0006 per ADR-0010's explicit scoping:

1. (Carried forward) `core/logging/` fills a blueprint §4 gap with no assigned folder in §6.
2. (Carried forward) Three root-level `core/` modules (`exceptions.py`, `schemas.py`, `interfaces.py`) are shared leaves with no assigned home.
3. (Carried forward) `core/graph/state.py` is a shared leaf contract `core/agents` may import, distinct from the rest of `core/graph`.
4. **(New) `core/memory` and `core/knowledge` own their own persistence/registration the same way `core/db` owns the domain schema** — `core/memory/db_models.py`/`repository.py` reuse `core.db.BaseRepository` rather than inventing a second persistence pattern, and neither layer imports `core/agents`/`core/graph` (verified by manual `grep`, since `scripts/check_dependency_rules.py` only mechanically checks the streamlit/fastapi-import rule — same known gap noted in the prior session).

No approved architectural decision has been reversed. `docs/roadmap.md`'s M6 checkbox remains unchecked — the memory/knowledge framework is implemented, but M6's own demo criterion (a real ChromaDB backend, populated knowledge data, the Threat Timeline/AI Analyst Chat UI) needs M1/M2's concrete agents and real domain/knowledge data first.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: UUID surrogate PKs via `Entity`; `Tool`/`Agent` Protocol variance; `Service` is not a Protocol; ruff format only; FastAPI `Annotated[Type, Depends(...)]` style; cursor pagination by UUID `id`; the Coordinator delegates planning and never executes agents itself; two-tier error handling in `BaseAgent`/`workflow_engine.py`; reducer-based `CaseInvestigationState`; `core/graph/routing.py` not `router.py`; numpy currently uninstalled — watch for reintroduction when `chromadb` lands in M6.)*

**New this session:**

- **`core/memory`/`core/knowledge` own their own SQLite persistence rather than waiting for domain models.** `MemoryRecordRow.case_id` is a plain UUID column, not a foreign key, because `Case`/`Evidence`/`Finding` don't exist yet (Milestone M1) and this layer must not block on them. Considered and rejected: deferring all memory persistence until M1's domain models land — rejected because it would force the first concrete specialist agent (M1) to *also* build its own memory persistence ad hoc, exactly the retrofit problem ADR-0009 already avoided for the agent framework. See ADR-0010.
- **ChromaDB stays exactly where ADR-0005 put it (M6, unbuilt).** `vector_store.py` ships `InMemoryVectorStore` as a genuinely functional reference implementation of the same `VectorMemory` Protocol, explicitly documented (module docstring, README, ADR-0010 "Consequences") as not a production substitute, so a future reviewer can't mistake "the Protocol is implemented" for "the production backend is implemented."
- **The deterministic text embedder uses `hashlib`, not Python's builtin `hash()`.** `hash()` on `str` is salted per-process (`PYTHONHASHSEED`) for security/DoS-resistance; using it would have made a "deterministic" embedder silently non-deterministic across process restarts — caught before it became a subtle test-flakiness bug, not assumed correct from the pattern's name.
- **`core/memory/metrics.py` does not subscribe to `core.graph.events.EventBus`,** unlike `core/graph/metrics.py`'s `MetricsCollector`. `core/memory` is a leaf layer per `docs/dependency-rules.md` and must never import `core/graph` — the memory-layer metrics collector is a small, self-contained, explicitly-constructed class instead, deliberately not reusing the graph layer's event-bus pattern even though the shape rhymes.
- **`MemoryRegistry` is generic (`MemoryRegistry[BackendT]`), unlike `AgentRegistry`/`ToolRegistry`.** Memory backends don't share one common base class the way agents/tools do (a `VectorMemory` and a `ConversationMemory` are structurally unrelated Protocols) — genericity avoids forcing an artificial shared interface just to reuse the registry pattern.
- **`sqlalchemy.CursorResult` is asserted (not just cast) in `MemoryRepository.delete_expired`.** `AsyncSession.execute()`'s static return type (`Result[Any]`) doesn't expose `.rowcount` even though a `DELETE`/`UPDATE` statement always returns a `CursorResult` at runtime — an `assert isinstance(...)` closes the mypy gap without a blind `# type: ignore`, verified against the real SQLAlchemy behavior via the passing `test_memory_repository.py`/`test_memory_lifecycle.py` tests, not assumed from the type stub alone.

---

## Public Interfaces

*(M0/M3 interfaces — `core.config`, `core.logging`, `core.exceptions`, `core.schemas`, `core.interfaces`, `core.db`, `core.agents.*`, `core.tools.*`, `core.graph.*`, `apps.api.*` — unchanged from prior sessions.)*

**Memory contracts:** `core.memory.interfaces.{ShortTermMemory, CaseMemory, LongTermMemory, VectorMemory, SimilarResult}` (unchanged Protocols) plus `core.memory.models.{MemoryScope, MemoryPriority, MemoryRecord, MemoryQuery, MemoryQueryResult, ConversationRole, ConversationTurn}`.

**Memory persistence:** `core.memory.db_models.MemoryRecordRow`, `core.memory.repository.MemoryRepository`.

**Memory implementations:** `core.memory.session_memory.SessionMemory`, `core.memory.case_memory.SQLiteCaseMemory`, `core.memory.conversation_memory.{ConversationMemory, InMemoryConversationMemory}`, `core.memory.vector_store.{TextEmbedder, HashingTextEmbedder, InMemoryVectorStore, NullVectorStore}`, `core.memory.long_term.LongTermMemoryManager`.

**Memory infrastructure:** `core.memory.lifecycle.{DEFAULT_RETENTION, CleanupReport, MemoryLifecycleManager}`, `core.memory.context_builder.{AssembledContext, ContextBuilder, DEFAULT_MAX_CHARS}`, `core.memory.context_serializer.ContextSerializer`, `core.memory.metrics.{MemoryMetrics, MemoryMetricsCollector}`, `core.memory.registry.{MemoryRegistry, default_memory_registry}`, `core.memory.manager.MemoryManager`.

**Knowledge contracts:** `core.knowledge.models.{KnowledgeSourceType, KnowledgeDocument, KnowledgeQuery, KnowledgeSearchResult}`, `core.knowledge.interfaces.{KnowledgeSource, KnowledgeRetriever}`, `core.knowledge.registry.{KnowledgeSourceRegistry, default_knowledge_registry}`, `core.knowledge.retrieval.KeywordKnowledgeRetriever`.

No domain (Case/Evidence/Finding) models/schemas, parsers, concrete specialist agents, concrete tools, ChromaDB backend, or populated knowledge data exist as public interfaces yet.

---

## Remaining Work

Unchanged in substance from the prior session's plan (see `docs/roadmap.md`), except M6's framework piece is now done:

1. **M1 — First real module, single agent, no orchestration.** `core/db/models.py` (`Case`, `Evidence`, `Finding`, `MitreTechnique`, `TimelineEvent`, `Report`) + first Alembic migration; `core/parsers/syslog_parser.py`; `core/tools/scoring.py`; `core/agents/soc_analyst_agent.py` (registered via `AgentRegistry`, added to `investigation_graph.py`); first real `/api/v1` route + `core/services/case_service.py`. This agent should be constructed with a real `core.memory.case_memory.SQLiteCaseMemory` — the first concrete use of this session's memory layer.
2. **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE Agent (the first concrete `core.knowledge.interfaces.KnowledgeSource`, registered into `KnowledgeSourceRegistry`); Phishing Investigation Agent + email parser + `core/security/prompt_guard.py`.
3. **M3 — remaining piece: wire real agents through the now-implemented framework.** Unchanged from the prior session's note.
4. **M4 — Remaining specialist modules.**
5. **M5 — Incident Response synthesis + Reporting.**
6. **M6 — remaining piece: swap `InMemoryVectorStore` for a real ChromaDB backend** (same `VectorMemory` Protocol, no caller changes), populate real MITRE/OWASP/threat-intel/playbook/detection-rule/investigation-template knowledge sources, Threat Timeline cross-evidence view, MITRE ATT&CK matrix heatmap, wire the AI Analyst Chat UI to `MemoryManager.get_conversation`/`add_conversation_turn`. Watch for the numpy/mypy interaction noted in the prior session when `chromadb` is installed.
7. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md`/`03_constitution.md` don't exist; `make migrate`/`make seed` are no-ops; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no performance/load testing; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix — this session's `core/memory`/`core/knowledge` layering was verified manually via `grep`; numpy is not currently installed.)*

- **`InMemoryVectorStore` is O(n) brute-force cosine similarity.** Fine for tests/local dev/small case volumes; will not scale to a real multi-case corpus the way ChromaDB's indexing would. This is by design (a testable reference implementation, not a production backend) but a future engineer should not extend its use past that scope without re-reading ADR-0010.
- **`HashingTextEmbedder` is not a semantic embedder.** Two paraphrased sentences with different words will not score as similar — documented in its own docstring. A real semantic embedder (LLM-provider-backed) is the intended production swap behind the same `TextEmbedder` Protocol.

---

## Dependencies

Runtime (`requirements.txt`): unchanged list from the prior session — no new third-party dependency was introduced this session (SQLite persistence reuses the already-installed `sqlalchemy`/`aiosqlite`; the embedder uses only the stdlib `hashlib`/`math`). `chromadb`, `streamlit`, and all parser/reporting libraries remain pinned for future milestones but not yet imported anywhere.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`), with one prior commit: `eae4fb8 feat: initial commit — engineering foundation + multi-agent framework` (M0 + the Multi-Agent Framework). This session's Memory & Knowledge Layer work is **uncommitted**:

- Modified: `CHANGELOG.md`, `context/current_state.md`, `core/knowledge/README.md`, `core/memory/README.md`, `docs/roadmap.md`.
- Untracked (new): `docs/adr/0010-memory-knowledge-layer-shape.md`, all of `core/knowledge/{models,interfaces,registry,retrieval}.py`, all of `core/memory/{models,db_models,repository,session_memory,case_memory,conversation_memory,vector_store,long_term,lifecycle,context_builder,context_serializer,metrics,registry,manager}.py`, and 17 new `tests/unit/test_{memory,knowledge}_*.py` files.

The working tree is in a complete, self-consistent, fully-tested state (245 tests passing — 228 unit + 17 integration — mypy/ruff/dependency-rules clean) but has not yet been committed; commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement Milestone M1 exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: add `core/db/models.py` defining `Case`, `Evidence`, `Finding`, `MitreTechnique`, `TimelineEvent`, and `Report` (each inheriting `core.db.Entity`, per `context/01_blueprint.md` §8 and `context/03_engineering_constitution.md` §7), generate the first real Alembic migration against them, implement `core/parsers/syslog_parser.py` (a deterministic syslog/firewall-log parser producing a typed `NormalizedEvidence` model, tested against `data/sample_evidence/ssh_auth.log` and at least one malformed-input fixture), implement `core/tools/scoring.py` as a concrete `BaseTool` subclass, and implement `core/agents/soc_analyst_agent.py` as a concrete `BaseAgent` subclass — constructed with a real `core.memory.case_memory.SQLiteCaseMemory` (this session's memory layer) rather than `None`, registered into `AgentRegistry` and wired into `core/graph/investigation_graph.py` following `docs/agent-design.md`'s "Adding a new agent" section. Wire it through `core/services/case_service.py` (which should call `core.graph.investigation_graph.run_investigation`) and one real `/api/v1` route (`apps/api/routers/cases.py`). Do not build the OWASP/Vulnerability/Phishing/etc. agents yet, and do not populate any MITRE/OWASP knowledge data yet — those are later milestones. Preserve every existing file and architectural decision described in this document, including the Multi-Agent Framework and the Memory & Knowledge Layer built in prior sessions; only extend them.
