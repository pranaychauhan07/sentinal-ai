# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Still nothing cybersecurity-related exists — no domain models, no parsers, no concrete specialist agent.** What is now complete, beyond the M0 engineering foundation, is the **Multi-Agent Framework**: the reusable agent/tool/workflow infrastructure every future specialist agent will be built on top of. Built ahead of the milestone schedule (normally M3) at explicit user direction — framework-first, validated by its own tests, before any domain-specific agent exists. Full design rationale: `docs/adr/0009-multi-agent-framework-shape.md`.

### M0 foundation (unchanged from prior session)

- **Configuration** — `core/config/`: pydantic-settings `Settings`, `Environment`/`LLMProvider` enums, cached `get_settings()`.
- **Structured logging** — `core/logging/`: structlog + stdlib integration, context-variable binding helpers (request/case/agent/correlation IDs), `log_execution_time` decorator.
- **Shared contracts** — `core/exceptions.py`, `core/schemas.py`, `core/interfaces.py` (root-level leaves, importable by every layer).
- **Database foundation** — `core/db/`: `Base`, `Entity` (UUID surrogate PK), `Database`, `BaseRepository`, Alembic scaffolding. No domain models yet.
- **FastAPI application** — `apps/api/`: app factory, middleware, exception handlers, dependencies, `/health` `/ready` `/version`, empty `/api/v1` router.
- **Developer experience / governance** — full directory skeleton, root engineering files, Docker, `.github/`, full `docs/` set, ADRs 0001–0008, sample evidence fixtures.

### Multi-Agent Framework (new this session)

- **`core/agents/`**:
  - `confidence.py` — `ConfidenceLevel` (CERTAIN/HIGH/MEDIUM/LOW/UNKNOWN), `ConfidenceScore` (frozen Pydantic value object), `classify_confidence()`, `.deterministic()`/`.llm_fallback()` constructors matching constitution §4.6's thresholds exactly.
  - `contracts.py` — `ExecutionStatus`, `ExecutionMetadata`, `AgentCapability`, `AgentIdentity`, `PlannedStep`, `ExecutionPlan` (with `entry_steps`/`is_empty`), `AgentExecutionResult`. Zero domain content — pure framework data shapes.
  - `base.py` — `BaseAgent`: template-method base. Subclasses implement only `execute()`; `__call__` (final, matches constitution §4.1 exactly) owns logging-context binding, timing, catch-all error handling (converts any exception from `execute()` into a degraded/failed `AgentExecutionResult` — never escapes), and folds the result onto `CaseInvestigationState` (`thoughts`, `agent_outputs`, `confidence_scores`, `execution_history`, `errors`). `use_tool(name, args)` enforces the agent's declared `tools_used`. Optional `tool_registry`/`case_memory` constructor dependencies.
  - `registry.py` — `AgentRegistry` (explicit, injectable; `register`/`get`/`has`/`find_by_capability`/`list_identities`), `default_agent_registry()` (`lru_cache` process-wide singleton, matching `core.config.get_settings()`'s pattern).
  - `coordinator.py` — `CoordinatorAgent(BaseAgent)`: routes empty/uncapable cases to manual triage; otherwise calls `PlanningAgent` directly (a plain Python call, not a graph edge) and writes the resulting `ExecutionPlan` onto state. **Never executes agents itself** — that's the graph's job.
  - `planning_agent.py` — `PlanningAgent(BaseAgent)`: matches `state.metadata["required_capabilities"]` (generic string tags) against every registered agent's declared `AgentCapability`, builds an `ExecutionPlan`, degrades confidence on partial matches, excludes the Coordinator/Planner themselves from being matched as plan targets (`RESERVED_FRAMEWORK_AGENT_NAMES`).
- **`core/tools/`**:
  - `base.py` — `BaseTool`: template-method base. `run()` is the only method subclasses implement; `__call__` owns validation, permission checks (`requires_approval`), timeout enforcement (`ThreadPoolExecutor`-based, only for `is_io_bound` tools), bounded retry (I/O-bound only — deterministic tools never retry, per constitution §5/§4.8), an opt-in in-process cache, and logging/`ToolExecutionMetadata`.
  - `registry.py` — `ToolRegistry`, `default_tool_registry()`.
- **`core/memory/interfaces.py`** — `ShortTermMemory`/`CaseMemory`/`LongTermMemory`/`VectorMemory` `Protocol`s. **Abstraction only** — no implementation, per this milestone's explicit scope. `short_term.py`/`long_term.py` (concrete) remain Milestone M6.
- **`core/graph/`**:
  - `state.py` (extended) — `CaseInvestigationState` gained `execution_plan`, `agent_outputs`, `confidence_scores`, `intermediate_results`, `metadata`, `extensions`, `execution_history`, `errors` (new `ErrorRecord` model), `extracted_indicators`. List/dict fields use `Annotated[..., reducer]` (`operator.add` for lists, a local `_merge_dicts` for dicts) so independent agents can write concurrently in the same LangGraph superstep without `InvalidUpdateError`.
  - `workflow_engine.py` — `WorkflowEngine`: compiles registered `BaseAgent`s into a real `langgraph.graph.StateGraph`. `add_agent_node`/`set_entry`/`add_conditional_edges` (deferred — path_map resolved lazily at `compile()` so nodes can be added after routing is registered)/`add_edge`/`compile`/`run`. Every node is wrapped to run the agent against a **private deep copy** of state (never the shared input — see the concurrency bug below) and diff the result into a minimal reducer-safe partial update; wraps with `RetryPolicy`, `FailureRecoveryPolicy`, and `EventBus` publication uniformly.
  - `routing.py` (named to match blueprint §6, not `router.py`) — `route_from_coordinator`: reads `state.execution_plan`/`requires_manual_triage`, returns the next node name(s) or `END`.
  - `investigation_graph.py` — `build_investigation_graph()`/`run_investigation()`. Today wires **only the Coordinator** as a graph node (Planner is called directly by the Coordinator, not a graph node). Left uncompiled on return so callers/future milestones can add specialist nodes before running.
  - `events.py` — `EventType`, `WorkflowEvent`, `EventBus` (explicit pub/sub, `default_event_bus()` singleton with `structlog_listener` subscribed by default).
  - `retry.py` — `RetryPolicy`, `run_with_retry()` (sync, exponential backoff, only retries `policy.retryable_exceptions`).
  - `failure_recovery.py` — `RecoveryAction` (CONTINUE_DEGRADED/MANUAL_TRIAGE/ABORT_WORKFLOW), `FailureRecoveryPolicy`, `recover()`.
  - `metrics.py` — `AgentMetrics`, `WorkflowMetrics`, `MetricsCollector` (subscribes to `EventBus`, never touches nodes directly).
  - `execution_context.py` — `ExecutionContext`, `execution_scope()` (binds/clears case_id/investigation_run_id logging context for one full workflow run).
- **Testing** — 86 new tests (158 total, up from 72), covering confidence/contracts/state, `BaseAgent`/`BaseTool` lifecycle and error handling, both registries, `CoordinatorAgent`/`PlanningAgent`, every `core/graph` module, and an integration test running the **real compiled `StateGraph`** end-to-end (manual triage path, single-node path, parallel fan-out with fake non-domain specialist agents, partial-capability-match path). mypy (strict on `core/`), ruff, `ruff format`, and `scripts/check_dependency_rules.py` all pass.

**Verified with a live, non-pytest end-to-end run**, not just green test output: a scratch script (`build_investigation_graph()` + fake, non-domain specialist agents) exercised (1) empty-case → manual triage, (2) mixed evidence → two specialists fanning out in the *same* LangGraph superstep with findings merging correctly and no duplication, (3) a simulated transient failure being retried once by `RetryPolicy` and recovering (`requires_manual_triage` stayed `False`), and (4) a partial capability match degrading plan confidence to `0.5` while still running the matched agent. All four scenarios printed real structlog output and passed their assertions.

**A real concurrency bug was found and fixed during this session, not assumed away:** LangGraph shares the same input object across sibling nodes scheduled in one superstep. Since `BaseAgent` mutates `CaseInvestigationState` in place, two parallel specialist nodes both mutating the same shared object caused duplicated `findings` entries (verified with a scratch reproduction before it reached the checked-in test suite). Fixed in `workflow_engine.py`: every node now runs the agent against its own `state.model_copy(deep=True)` and diffs against the *original*, never-mutated `state` parameter. Documented in ADR-0009 point 5.

**Explicitly NOT built:** any domain DB model (`Case`/`Evidence`/`Finding`/etc.), any parser, any concrete specialist agent (SOC Analyst, Threat Hunting, Phishing, Vulnerability, OWASP, Linux Security, Incident Response, MITRE, Report Generator, Memory), any tool implementation (CVSS calculator, risk scoring, etc.), any memory *implementation* (interfaces only), `core/security/*`, `core/reporting/*`, any `apps/web` code, any `/api/v1` domain route. No git repository exists.

---

## Repository Status

```
apps/
  api/            FastAPI app (unchanged)                          [implemented]
  web/            Streamlit frontend                                [README only]
core/
  config/         (unchanged)                                       [implemented]
  logging/        (unchanged)                                       [implemented]
  exceptions.py, schemas.py, interfaces.py                          [implemented]
  agents/         base.py, registry.py, confidence.py, contracts.py,
                   coordinator.py, planning_agent.py                 [implemented — framework only]
  tools/          base.py, registry.py                               [implemented — framework only]
  memory/         interfaces.py                                      [implemented — abstraction only]
  graph/          state.py (extended), workflow_engine.py, routing.py,
                   investigation_graph.py, events.py, retry.py,
                   failure_recovery.py, metrics.py, execution_context.py
                                                                       [implemented — framework only]
  db/             (unchanged, no domain models)                      [implemented, no domain models]
  parsers/        (empty — README only)                              [not started]
  knowledge/      (empty — README only)                              [not started]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       (empty — README only)                              [not started]
data/             (unchanged)
tests/
  unit/           26 test modules (~110 tests)
  integration/    4 test modules (~48 tests, including
                   test_investigation_graph.py — real compiled StateGraph)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (10 ADR files incl. template)
                   + docs/diagrams/multi-agent-framework.mmd (new)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          (unchanged)
.github/          (unchanged)
```

~180 tracked files total (up from 150). Root config/governance files unchanged and current, except `pyproject.toml` (mypy override note removed — see Key Decisions) and `requirements.txt`/`CHANGELOG.md`/`docs/roadmap.md`/`README.md` updated this session.

**Naming note carried forward:** `context/02_repository.md` and `context/03_constitution.md` still do not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`. A prompt this session referenced both non-existent filenames again — flagged and worked around identically to the prior session's note.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, with one new documented clarification (not a redesign) beyond the two carried forward from M0:

1. (Carried forward) `core/logging/` fills a blueprint §4 gap with no assigned folder in §6.
2. (Carried forward) Three root-level `core/` modules (`exceptions.py`, `schemas.py`, `interfaces.py`) are shared leaves with no assigned home.
3. **(New) `core/graph/state.py` is a shared leaf contract `core/agents` may import**, distinct from `core/graph/investigation_graph.py`/`routing.py`/`workflow_engine.py` which remain off-limits to `core/agents`. This was a pre-existing gap in `docs/dependency-rules.md` (rule 4 never listed `core/graph/state.py` even though constitution §4.1's literal agent signature requires importing it) — closed explicitly in `docs/dependency-rules.md` and recorded in `docs/adr/0009-multi-agent-framework-shape.md` point 7, rather than left as a silent, unenforced exception.

The dependency direction rule is still mechanically enforced by `scripts/check_dependency_rules.py` (streamlit/fastapi import scan only — it does not check sibling-`core/`-layer violations; those were verified manually this session via `grep` across `core/tools`, `core/memory`, `core/agents`).

No approved architectural decision has been reversed. `docs/roadmap.md`'s M3 checkbox remains unchecked — the framework is implemented, but M3's own demo criterion (real mixed evidence routing to real specialist agents) needs M1/M2's concrete agents first.

---

## Key Decisions

*(Carried forward from M0 — still true, unchanged: UUID surrogate PKs via `Entity`; `Tool` Protocol variance; `Service` is not a Protocol; ruff format only, no Black; FastAPI `Annotated[Type, Depends(...)]` dependency style; cursor pagination ordered by UUID `id`; `scripts/run_migrations.sh`/`seed_sample_data.py` are honest no-op stubs.)*

**New this session:**

- **The Coordinator delegates planning; it never executes agents itself.** `CoordinatorAgent.execute()` calls `PlanningAgent` as a plain Python function and writes an `ExecutionPlan` onto state — the LangGraph edges (`routing.py`) do the actual fan-out/execution. Considered and rejected: the Coordinator imperatively looping over planned agents itself, which would make it a second, competing execution engine parallel to LangGraph's own (defeats ADR-0003's reason for choosing LangGraph). See ADR-0009 point 3.
- **Two-tier error handling, deliberately.** `BaseAgent` catches everything a concrete agent's `execute()` can raise (documented fallback tier, constitution §4.7). `workflow_engine.py` separately wraps every node with its own retry/failure-recovery for exceptions escaping `BaseAgent.__call__` itself — a framework-bug tier, constitution §9. Not redundant: they cover genuinely different failure classes. See ADR-0009 point 4.
- **Reducer-based state, verified empirically before relying on it.** `CaseInvestigationState`'s list/dict fields are `Annotated` with merge reducers because LangGraph rejects concurrent same-field writes otherwise (confirmed with a scratch script against the installed `langgraph` package, not assumed from docs). See ADR-0009 point 5 and the concurrency-bug note above.
- **`add_conditional_edges`'s path_map is resolved lazily at `compile()`, not at call time.** An earlier version resolved it eagerly (at the `add_conditional_edges` call), which silently broke routing to any node added afterward — caught by an integration test failing with a LangGraph `KeyError`, not assumed correct.
- **`core/graph/routing.py`, not `router.py`.** Initially implemented as `router.py`; renamed to match blueprint §6's explicit filename after cross-checking the blueprint text, before this became yet another undocumented naming drift.
- **`numpy` was uninstalled from the environment.** Installing `langgraph` transitively pulled in a numpy version (2.5.0) whose bundled type stubs use Python-3.12-only syntax, which broke `mypy core` (a hard parse error, not suppressible via per-module `ignore_errors` since it fails before override application). `pip show numpy` confirmed nothing in the installed environment actually required it (`Required-by:` was empty) — uninstalling it was the correct fix, not a workaround. **Risk carried forward:** a future milestone that installs `chromadb` (Milestone M6) will reintroduce numpy as a real dependency; whoever does that should re-check `mypy core` and, if the same stub-syntax issue recurs, pin a numpy version compatible with the project's `python_version = "3.11"` mypy target rather than raising that target (which would permit 3.12+-only syntax in project code, contradicting `requires-python = ">=3.11"`).
- **One `# type: ignore[call-overload]`, precisely scoped and documented, on `WorkflowEngine.add_agent_node`'s `self._graph.add_node(...)` call.** LangGraph's `add_node` overloads are generic over its own TypedDict/dataclass/BaseModel node-input protocols in a way mypy can't unify with a plain `(CaseInvestigationState) -> dict[str, Any]` node function, despite this being the exact dict-partial-update shape LangGraph documents and despite runtime behavior being verified via the integration test. Not a workaround for our own bug — verified as a LangGraph stub-precision limitation before suppressing it.

---

## Public Interfaces

*(M0 interfaces — `core.config`, `core.logging`, `core.exceptions`, `core.schemas`, `core.interfaces`, `core.db`, `apps.api.*` — unchanged from prior session, see below for the new surface.)*

**Confidence:** `core.agents.confidence.{ConfidenceLevel, ConfidenceScore, classify_confidence, DETERMINISTIC_CONFIDENCE, LLM_FALLBACK_CONFIDENCE_CEILING}`.

**Agent contracts:** `core.agents.contracts.{ExecutionStatus, ExecutionMetadata, AgentCapability, AgentIdentity, PlannedStep, ExecutionPlan, AgentExecutionResult}`.

**Agents:** `core.agents.base.BaseAgent`, `core.agents.registry.{AgentRegistry, default_agent_registry}`, `core.agents.coordinator.CoordinatorAgent`, `core.agents.planning_agent.{PlanningAgent, RESERVED_FRAMEWORK_AGENT_NAMES}`.

**Tools:** `core.tools.base.{BaseTool, ToolExecutionStatus, ToolExecutionMetadata, ToolPermissionDeniedError, ToolTimeoutError}`, `core.tools.registry.{ToolRegistry, default_tool_registry}`.

**Memory:** `core.memory.interfaces.{ShortTermMemory, CaseMemory, LongTermMemory, VectorMemory, SimilarResult}` — Protocols only, no implementation.

**Graph state:** `core.graph.state.{CaseInvestigationState, AgentThought, ErrorRecord}` — `CaseInvestigationState` now carries `execution_plan`, `agent_outputs`, `confidence_scores`, `intermediate_results`, `metadata`, `extensions`, `execution_history`, `errors`, `extracted_indicators` in addition to the M0 fields.

**Graph/workflow:** `core.graph.workflow_engine.WorkflowEngine`, `core.graph.routing.route_from_coordinator`, `core.graph.investigation_graph.{build_investigation_graph, run_investigation}`, `core.graph.events.{EventType, WorkflowEvent, EventBus, default_event_bus, structlog_listener}`, `core.graph.retry.{RetryPolicy, run_with_retry}`, `core.graph.failure_recovery.{RecoveryAction, FailureRecoveryPolicy, recover}`, `core.graph.metrics.{AgentMetrics, WorkflowMetrics, MetricsCollector}`, `core.graph.execution_context.{ExecutionContext, execution_scope}`.

No domain (Case/Evidence/Finding) models/schemas, parsers, concrete specialist agents, or concrete tools exist as public interfaces yet.

---

## Remaining Work

Unchanged in substance from the prior session's plan (see `docs/roadmap.md`), except M3's framework piece is now done:

1. **M1 — First real module, single agent, no orchestration.** `core/db/models.py` (`Case`, `Evidence`, `Finding`, `MitreTechnique`, `TimelineEvent`, `Report`) + first Alembic migration; `core/parsers/syslog_parser.py`; `core/tools/scoring.py` (subclassing the now-implemented `BaseTool`); `core/agents/soc_analyst_agent.py` (subclassing the now-implemented `BaseAgent`, registered via `AgentRegistry`, added to `investigation_graph.py` per the pattern `docs/agent-design.md` now documents); first real `/api/v1` route + `core/services/case_service.py` (which becomes the real caller of `run_investigation()`).
2. **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE Agent; Phishing Investigation Agent + email parser + `core/security/prompt_guard.py`.
3. **M3 — remaining piece: wire real agents through the now-implemented framework.** The framework itself (Coordinator, Planner, `WorkflowEngine`, registries) is done; what's left is registering M1/M2's real agents and confirming the mixed-evidence fan-out demo works end-to-end with real (not fake/test-double) specialist agents.
4. **M4 — Remaining specialist modules.** Vulnerability Assessment Agent, OWASP Security Agent, Linux Security Agent, Threat Hunting Agent.
5. **M5 — Incident Response synthesis + Reporting.**
6. **M6 — Memory implementation + Threat Timeline + UX polish.** Concrete `core/memory/short_term.py`/`long_term.py` implementing this session's `Protocol`s; watch for the numpy/mypy interaction noted above when `chromadb` is installed.
7. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: no git repository exists; `context/02_repository.md`/`03_constitution.md` don't exist; `make migrate`/`make seed` are no-ops; `apps/web` has no code; harmless Starlette deprecation warning in test output; no performance/load testing; no CI has ever actually run on GitHub.)*

- **`scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule** — it does not mechanically verify sibling-`core/`-layer violations (e.g. "does `core/tools` import `core/agents`"). This session's layering was verified manually via `grep` across `core/tools/*.py`, `core/memory/*.py`, `core/agents/*.py`; a future session extending this script to check the full matrix in `docs/dependency-rules.md` (not just rule 1) would remove the need for that manual step.
- **`numpy` is not currently installed**, having been removed this session to unblock `mypy core` (see Key Decisions). This is fine today (nothing imports it), but will matter again once `chromadb` (Milestone M6) is installed.

---

## Dependencies

Runtime (`requirements.txt`): unchanged list from M0, but **`langgraph` is now an actively-imported, exercised dependency** (previously pinned but unused). `langchain`, `langchain-openai`, `langchain-google-genai`, `langchain-community`, `chromadb`, `streamlit`, and all parser/reporting libraries remain pinned for future milestones but not yet imported anywhere.

Dev (`requirements-dev.txt`): unchanged from M0.

Installed-but-not-in-requirements.txt: `langchain-core`, `langgraph-checkpoint`, `langgraph-prebuilt`, `langgraph-sdk`, `langsmith`, and their transitive dependencies — all pulled in automatically by `pip install langgraph`; none are imported directly by this project's code.

---

## Current Git Status

No git repository exists in this project directory. A commit was requested and then interrupted before `git init` ran — still no repository, no commits, nothing staged. If/when one is initialized, everything under the project root except the paths listed in `.gitignore` should be added and committed as the initial commit — there are no partial/in-progress edits to selectively stage; the working tree is in a complete, self-consistent, fully-tested, and live-verified state as described above.

---

## Next Recommended Prompt

> Implement Milestone M1 exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: add `core/db/models.py` defining `Case`, `Evidence`, `Finding`, `MitreTechnique`, `TimelineEvent`, and `Report` (each inheriting `core.db.Entity`, per `context/01_blueprint.md` §8 and `context/03_engineering_constitution.md` §7), generate the first real Alembic migration against them, implement `core/parsers/syslog_parser.py` (a deterministic syslog/firewall-log parser producing a typed `NormalizedEvidence` model, tested against `data/sample_evidence/ssh_auth.log` and at least one malformed-input fixture), implement `core/tools/scoring.py` as a concrete `BaseTool` subclass (the now-implemented `core/tools/base.py` framework — do not reinvent validation/timeout/logging), and implement `core/agents/soc_analyst_agent.py` as a concrete `BaseAgent` subclass (the now-implemented `core/agents/base.py` framework — do not reinvent the lifecycle), registered into `AgentRegistry` and wired into `core/graph/investigation_graph.py` following the pattern documented in `docs/agent-design.md`'s "Adding a new agent" section. Wire it through `core/services/case_service.py` (which should call `core.graph.investigation_graph.run_investigation`) and one real `/api/v1` route (`apps/api/routers/cases.py`). Do not build the OWASP/Vulnerability/Phishing/etc. agents yet — those are later milestones. Preserve every existing file and architectural decision described in this document, including the Multi-Agent Framework built this session; only extend it.
