# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once
`v1.0.0` is tagged. Pre-1.0 releases are tagged per milestone
(`v0.1-foundation`, `v0.2-single-agent`, ...) as described in
`docs/roadmap.md`.

## [Unreleased]

### Added
- Repository foundation: full directory skeleton with per-folder purpose
  documentation, root engineering/config files, documentation set (including
  ADRs 0001–0008), GitHub governance files, and realistic sample evidence
  fixtures.
- `context/03_engineering_constitution.md`: the binding, project-wide
  engineering standard every future implementation must follow.
- Backend engineering foundation (no domain/business logic yet):
  - `core/config`: pydantic-settings `Settings`, `Environment`/`LLMProvider`
    enums, cached `get_settings()`.
  - `core/logging`: structlog + stdlib logging integration (JSON in
    production, console in dev/test, rotating file handler), request/case/
    agent/correlation-ID context binding, `log_execution_time` decorator.
  - `core/exceptions`, `core/schemas`, `core/interfaces`: shared exception
    hierarchy, API error/pagination/health envelopes, and `Repository`/
    `Agent`/`Tool` structural Protocols.
  - `core/graph/state.py`: minimal `CaseInvestigationState` (no agent logic).
  - `core/db`: async SQLAlchemy engine/session management, `Entity` base
    (surrogate UUID primary key convention), generic `BaseRepository`,
    Alembic migration scaffolding wired to async settings.
  - `apps/api`: FastAPI application factory, request-context middleware,
    standardized exception handlers, `/health`, `/ready`, `/version`
    endpoints, OpenAPI customization, auth/dependency-injection placeholders.
  - 72 tests (unit + integration), 98% coverage on all new code; mypy, ruff,
    and the `core/` dependency-rule check all pass.
- Multi-Agent Framework (`docs/adr/0009-multi-agent-framework-shape.md`) —
  the reusable agent/tool/workflow infrastructure, built ahead of the
  milestone schedule as pure framework with zero cybersecurity domain
  logic and no concrete specialist agent:
  - `core/agents`: `BaseAgent` (template-method lifecycle: identity,
    validation, tool/memory access, ReAct thought/confidence, structured
    logging, typed error handling), `AgentRegistry`, `ConfidenceScore`/
    `ConfidenceLevel`, the framework's shared Pydantic contracts
    (`ExecutionPlan`, `AgentExecutionResult`, `AgentCapability`, ...),
    `CoordinatorAgent` (delegates planning, never executes agents itself),
    `PlanningAgent` (capability-matching plan builder).
  - `core/tools`: `BaseTool` (template-method: validation, timeout,
    permission checks, bounded retry on I/O-bound tools only, caching,
    logging) and `ToolRegistry`.
  - `core/memory/interfaces.py`: `ShortTermMemory`/`CaseMemory`/
    `LongTermMemory`/`VectorMemory` Protocols — abstraction only, no
    implementation.
  - `core/graph`: `WorkflowEngine` (compiles registered agents into a real
    LangGraph `StateGraph`, with retry/failure-recovery/event-publication/
    metrics wired uniformly around every node), `routing.py`
    (`route_from_coordinator`), `investigation_graph.py`
    (`build_investigation_graph`/`run_investigation`), `events.py`
    (`EventBus`), `retry.py` (`RetryPolicy`), `failure_recovery.py`
    (`FailureRecoveryPolicy`), `metrics.py` (`MetricsCollector`),
    `execution_context.py`. `CaseInvestigationState` extended with
    `execution_plan`, `agent_outputs`, `confidence_scores`,
    `intermediate_results`, `execution_history`, `errors`, `metadata`,
    `extensions`, `extracted_indicators` — list/dict fields use
    `Annotated` reducers so independent agents can run in the same
    LangGraph superstep without conflicting (verified against the
    installed `langgraph` package's actual parallel-fanout behavior, which
    surfaced and fixed a real double-write bug before it reached the test
    suite — see the ADR).
  - 86 new tests (158 total), full mypy/ruff/dependency-rule pass. Added
    `langgraph` as an installed, actively-imported dependency (previously
    pinned in `requirements.txt` but unused).
  - `docs/dependency-rules.md` clarified: `core/agents` may import
    `core/graph/state.py` specifically (a shared state *contract*, not
    graph business logic) — a pre-existing gap between the constitution's
    literal agent-signature requirement and the dependency matrix, closed
    explicitly rather than left implicit.
- Memory & Knowledge Layer (`docs/adr/0010-memory-knowledge-layer-shape.md`)
  — built ahead of the milestone schedule (normally M6) as pure
  infrastructure, with zero cybersecurity domain logic and no populated
  knowledge data:
  - `core/memory/models.py`: `MemoryScope`/`MemoryPriority`/`MemoryRecord`/
    `MemoryQuery`/`MemoryQueryResult`/`ConversationTurn` typed contracts.
  - `core/memory/db_models.py` + `repository.py`: SQLite persistence for
    memory records via `core.db.BaseRepository`, indexed on
    `(scope, case_id)`, with scope/case/text/tag filtering and
    expiry-based bulk deletion.
  - Concrete implementations of every existing memory Protocol:
    `SessionMemory` (`ShortTermMemory`), `SQLiteCaseMemory` (`CaseMemory`,
    the first real backing for `BaseAgent`'s existing
    `case_memory` constructor parameter), `InMemoryVectorStore` +
    `NullVectorStore` (`VectorMemory` — a genuinely working brute-force
    cosine-similarity store plus a documented no-op fallback; ChromaDB
    itself remains M6, unbuilt, per ADR-0005/0006), `LongTermMemoryManager`
    (`LongTermMemory`, always-advisory per ADR-0006), and a new
    `ConversationMemory` Protocol + `InMemoryConversationMemory`
    implementation for case-scoped chat history.
  - `core/memory/vector_store.py` also ships a deterministic,
    dependency-free `HashingTextEmbedder` (`TextEmbedder` Protocol) so the
    vector store is exercisable end-to-end without an LLM provider call.
  - `core/memory/lifecycle.py`: `MemoryLifecycleManager` — per-scope TTL
    defaults and a `cleanup_expired()` pass, the reusable unit a future
    scheduled job calls.
  - `core/memory/context_builder.py` + `context_serializer.py`: filter →
    deduplicate → rank (priority, then recency) → truncate-to-budget
    context assembly, rendered to prompt text or a structured dict.
  - `core/memory/metrics.py`: self-contained `MemoryMetricsCollector`
    (hit/miss/write/eviction counters, retrieval timing) — deliberately
    independent of `core.graph.events.EventBus` since `core/memory` is a
    leaf layer that must never import `core/graph`.
  - `core/memory/registry.py` + `manager.py`: `MemoryRegistry` (generic
    named-backend lookup) and `MemoryManager` (the single facade wiring
    session/case/conversation/long-term memory, context assembly, and
    metrics together — every dependency optional and injected, degrading
    to advisory no-ops with nothing configured).
  - `core/knowledge/models.py`, `interfaces.py`, `registry.py`,
    `retrieval.py`: `KnowledgeSourceType` (MITRE/OWASP/threat-intel/
    playbook/detection-rule/investigation-template — no data populated),
    `KnowledgeSource`/`KnowledgeRetriever` Protocols,
    `KnowledgeSourceRegistry`, and a deterministic
    `KeywordKnowledgeRetriever`.
  - 70 new tests (228 total), full mypy/ruff/dependency-rule pass.
- Evidence Ingestion & Parser Framework
  (`docs/adr/0011-evidence-ingestion-pipeline-shape.md`) — built ahead of
  the milestone schedule (normally part of M1) as reusable, agent-independent
  infrastructure, with zero investigation/MITRE/agent logic:
  - `core/parsers/models.py`: the canonical evidence contract —
    `EvidenceType`, `Severity`, `EvidenceRecord` (per-event), `NormalizedEvidence`
    (per-artifact container with `ChainOfCustody`), every parser's one output shape.
  - `core/parsers/base.py`: `BaseParser` template method (mirrors
    `BaseTool`/`BaseAgent`'s shape) — owns encoding detection, fingerprinting,
    timing, metrics, logging, and the degrade-not-crash contract
    (a malformed artifact returns a zero-confidence result with the whole
    artifact preserved in `unparsed_fragments`, never a crash and never
    silently dropped data).
  - `core/parsers/registry.py`: plugin-capable `ParserRegistry` — aliases,
    versioning, priority-based tie-breaking, enable/disable, and
    `load_plugins()` via `importlib.metadata` entry points (`cdc.parsers`
    group) as a real, working external-extension seam.
  - `core/parsers/factory.py`: deterministic `select_parser` (declared type
    → extension → content-sniff ranking → `UnsupportedFormatError`).
  - `core/parsers/detection.py`, `validation.py`, `fingerprint.py`: stdlib-only
    MIME/encoding detection (no `chardet`/`python-magic` dependency added),
    upload-boundary validation (size caps, extension allowlist, path-traversal
    guard), and SHA-256 fingerprinting.
  - `core/parsers/metrics.py`, `events.py`, `audit.py`: self-contained parser
    metrics/event-publisher (independent of `core.graph.events.EventBus`, per
    the same leaf-layering reasoning as `core/memory/metrics.py`), and
    structured chain-of-custody audit logging.
  - Nine concrete parsers, each a `BaseParser` subclass: `ssh_auth`,
    `apache_access`, `apache_error`, `syslog` (generic RFC3164-ish fallback),
    `windows_event` (a CSV/XML **EVTX abstraction** — binary `.evtx` parsing
    is a documented future extension), `json_evidence`, `csv_evidence`,
    `nmap_xml` (via `defusedxml` — XXE/entity-expansion-safe, verified against
    an XXE-attempt fixture), `plain_text` (deterministic last-resort fallback).
  - `core/db/models/` (new package, first domain persistence): `Evidence`
    ORM model + `EvidenceStatus`, `case_id` a plain UUID column pending
    Milestone M1's `Case` model (extending the exact ADR-0010 precedent),
    plus its first Alembic migration and `core/db/evidence_repository.py`
    (`find_by_case`, `find_by_sha256` dedup, `mark_parsed`, `mark_failed`).
  - `core/services/evidence_service.py`: `EvidencePipeline`, the ten explicit
    stages (upload → validate → fingerprint → extract_metadata →
    select_parser → parse → normalize → persist → publish_event →
    notify_memory) + `ingest_evidence()` orchestrator. `core/services`
    importing `core/parsers`/`core/memory` directly is a documented,
    scoped exception to the "services only call `core/graph`" rule (ADR-0011),
    since evidence ingestion is deterministic and pre-investigation.
  - Two new mermaid diagrams (`docs/diagrams/evidence-ingestion-pipeline.mmd`,
    `parser-lifecycle.mmd`).
  - 107 new tests (352 total, up from 245), including adversarial fixtures
    (an XXE-attempt Nmap XML, truncated/malformed CSV and JSON, path
    traversal filenames, oversized/empty uploads, non-UTF8 byte content).
    mypy (strict on `core/`), `ruff check`/`format`, and
    `scripts/check_dependency_rules.py` all pass; the one new
    `core/services → core/parsers` edge was verified by manual grep to be
    exactly as scoped.
  - New dependency: `defusedxml` (runtime, XXE protection for
    `nmap_parser.py`) + `types-defusedxml` (dev, mypy stubs).

<!--
Template for future entries:

## [v0.X-milestone-name] - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...
-->
