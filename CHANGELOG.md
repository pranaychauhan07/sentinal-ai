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
