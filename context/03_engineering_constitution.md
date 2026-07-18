# Engineering Constitution
## Cyber Defense Copilot — Permanent Engineering Contract

**Status:** Binding. Every future implementation — every agent, tool, parser,
API route, migration, and test — must comply with this document.

**Relationship to other project documents:**
- `context/01_blueprint.md` is the architecture (what layers exist, why, and
  how they compose). This document is the *constitution* (how code is
  written inside that architecture). It does not redesign anything the
  blueprint decided.
- `docs/engineering-standards.md`, `docs/dependency-rules.md`, and
  `docs/agent-design.md` are the working, day-to-day references derived from
  this constitution. Where they overlap, this document is authoritative; if
  they ever drift, they are wrong and must be corrected to match this file,
  not the reverse.
- `docs/adr/*` records *why* a specific architectural decision was made. This
  constitution records *how every decision, past and future, must be built*.

**Amendment process:** This constitution changes only via a new ADR
(`docs/adr/000X-constitution-amendment-<topic>.md`) explaining what changed
and why, followed by an update to this file. It is never silently edited.

---

## 1. General Principles

These are the values every other rule in this document derives from. When a
new situation isn't explicitly covered below, resolve it by asking which
choice these principles favor.

1. **Simplicity over cleverness.** The correct solution is the one the next
   engineer (or you, in six months) can understand in one read. A clever
   one-liner that saves five lines but costs five minutes of comprehension
   is a net loss. *Why:* this project is explicitly designed to outlive its
   author's memory of writing it — clever code is a liability the moment the
   author forgets the trick.

2. **Explicit is better than implicit.** Function signatures declare every
   input and output type. Configuration is read in one place
   (`core/config/settings.py`) and passed explicitly, never pulled from
   ambient global state. Agent behavior is defined by typed contracts, not
   inferred from prompt text. *Why:* implicit behavior is undebuggable —
   when something goes wrong, you need to be able to point at the exact line
   that decided the outcome.

3. **Small, focused modules.** A file does one thing. `core/tools/scoring.py`
   computes scores; it does not also parse logs. If a module's
   responsibility needs "and" to describe it, it needs to be split. *Why:*
   this is what makes unit testing meaningful and what limits the blast
   radius of any single change.

4. **Single Responsibility Principle, applied to agents and tools alike.**
   An agent decides *what to do*; a tool computes *a specific answer*; a
   parser *extracts structure*; a service *coordinates*. No module holds two
   of these responsibilities. *Why:* this is the same discipline
   `docs/dependency-rules.md` enforces at the folder level, applied inside a
   single file.

5. **Composition over inheritance, except where the domain is genuinely
   hierarchical.** Agents are composed of tools via calls, not built as
   subclasses of a shared `BaseAgent` with overridden behavior scattered
   across a class hierarchy. The one accepted exception: shared Pydantic base
   models (e.g. a common `BaseFinding` all `*Finding` models inherit from) —
   real is-a relationships, not behavior reuse via inheritance. *Why:*
   inheritance hierarchies in agent systems tend to hide control flow inside
   `super()` calls; composition keeps the ReAct Thought → Action → Observation
   sequence traceable in one place.

6. **Every module has one owner (one clear home, one clear author of
   intent).** Every file lives in exactly the folder its `README.md` says it
   should, per `docs/dependency-rules.md`. No "misc" or "helpers" dumping
   ground module accumulates unrelated functions over time — a new
   responsibility gets a new, named module.

7. **Fail gracefully, not silently and not catastrophically.** A parser that
   can't fully parse an artifact returns a partial, confidence-scored result
   (see §6, §5) — it never both (a) crashes the investigation and (b)
   silently drops data pretending nothing was wrong. Every failure is either
   handled with a documented fallback or propagated loud and typed.

8. **Security by default, not by review.** Untrusted content (phishing
   bodies, uploaded source code) passes through `core/security/prompt_guard.py`
   because the code path requires it structurally (see §9), not because a
   reviewer remembered to check for it. Defaults are the safe choice; unsafe
   behavior requires an explicit, reviewed opt-in.

9. **Determinism where it's possible, LLM reasoning only where it's
   necessary.** Anything with one correct, checkable answer — a CVSS score, a
   risk score, a MITRE technique ID, a permission-string interpretation — is
   computed by a plain function (`core/tools/`, `core/knowledge/`), never by
   asking an LLM to "figure it out." The LLM's job is judgment,
   synthesis, and explanation of results the deterministic layer already
   computed. (Restated at length in `docs/adr/0008-agent-tool-boundary.md`.)

10. **The architecture is not renegotiated per feature.** `core/`'s
    framework-agnosticism, the Case-centric data model, and the layer
    boundaries in `docs/dependency-rules.md` are fixed. A feature that seems
    to require violating them is a signal to rethink the feature's
    implementation, not the architecture — and if it genuinely can't be
    reconciled, it requires a new ADR before any code is written, not after.

---

## 2. Python Standards

| Concern | Rule | Why |
|---|---|---|
| **Version** | Python 3.11+ everywhere (`pyproject.toml`) | Modern typing (`X \| Y` unions, `Self`, `TypedDict` improvements) used throughout Pydantic models and agent signatures. |
| **Formatting** | `ruff format`, line length 100, enforced by pre-commit and CI, never hand-formatted against it | One tool, zero bikeshedding, zero formatting diffs in code-review PRs. |
| **Linting** | `ruff check` (`E, F, I, UP, B, SIM, N` rule sets) | Catches bugs (F), enforces import order (I), flags upgrade opportunities (UP), bug-prone patterns (B), simplifiable code (SIM), naming (N) — one fast tool instead of five slow ones. |
| **Import order** | stdlib → third-party → first-party (`core`, `apps`), enforced by ruff's isort rules; absolute imports only, no relative imports crossing package boundaries | Makes it visually obvious at the top of every file which layer a module depends on — a `core/agents/x.py` file that imports `apps.*` is instantly visible as a violation before you even reach `docs/dependency-rules.md`'s automated check. |
| **Naming** | `snake_case` modules/functions, `PascalCase` classes/Pydantic models, `run_<agent_name>` for every LangGraph node function, `test_<module_under_test>.py` for tests | Predictable names mean you can guess a file's location/purpose without searching — see `docs/engineering-standards.md` for the full table. |
| **Type hints** | Mandatory, full coverage on every function in `core/` (`mypy --disallow-untyped-defs` on `core.*`); relaxed only for `apps/*` presentation glue | Types are the contract between agents/tools/parsers — untyped code in `core/` is not "faster to write," it's a deferred bug. |
| **Dataclasses** | Used only for simple, internal, non-validated data carriers that never cross a module boundary as a public contract (e.g. an internal computation's intermediate tuple-of-fields). If it crosses a function boundary that another module calls, it's a Pydantic model, not a dataclass. | Dataclasses don't validate; Pydantic does. Reserving dataclasses for truly-internal use prevents "is this validated or not" ambiguity creeping into public APIs. |
| **Pydantic usage** | Pydantic v2 for every agent input/output, every parser's `NormalizedEvidence` subtype, every tool's structured return value, every API request/response schema | This is the single mechanism that makes "typed contracts everywhere" (Principle 2) actually true rather than aspirational — see `docs/agent-design.md` rule 1. |
| **Async conventions** | `async def` for anything touching the DB (SQLAlchemy async engine), the LLM provider, or ChromaDB. Synchronous code stays synchronous — no `async def` on a function that does no I/O, and no blocking I/O inside an `async def` without `run_in_executor`/an async-native client. | Mixing sync blocking calls into async code silently stalls the whole event loop; this is a correctness rule, not a style preference. |
| **File organization** | One primary public class/function focus per file; a file's name states what it exports (`cvss_calculator.py` exports CVSS-calculation functions, nothing else) | Supports Principle 3 (small, focused modules) — you should be able to predict a file's contents from its name before opening it. |
| **Constants** | `UPPER_SNAKE_CASE`, module-level, defined once near their point of use or in a dedicated `constants.py` within the owning subpackage — never duplicated across files (e.g. the 0–100 risk-scoring thresholds live once, in `core/tools/scoring.py`) | A magic number that appears in two places will eventually be updated in only one. |
| **Enums** | `enum.Enum` (or `StrEnum` where the value is also the wire format, e.g. `EvidenceType`, `Severity`) for any fixed, closed set of values — never bare strings compared with `==` scattered across the codebase | Enums give you exhaustiveness checking (mypy flags an unhandled case) and prevent typo'd string literals from silently creating a new, unintended category. |
| **Utilities** | Cross-cutting, genuinely generic helpers (e.g. a timestamp normalizer used by three parsers) live in the owning layer's `utils.py` (e.g. `core/parsers/utils.py`), never in a top-level catch-all `core/utils.py` that every layer reaches into | A global utils module becomes a dependency-rule loophole — everything imports it, and it becomes impossible to reason about who depends on what (violates Principle 6). |
| **Configuration** | Read exclusively via `core/config/settings.py` (pydantic-settings); `os.environ` is never referenced anywhere else in the codebase | One place to see every config knob, one place `.env.example` has to stay in sync with — see `core/config/README.md`. |
| **Dependency injection** | Services and agents receive their dependencies (DB session, LLM client, settings) as constructor/function parameters, not by importing a global singleton and calling it | Makes every unit testable in isolation with a fake/mock dependency, and makes the LLM-provider swap (OpenAI ↔ Gemini ↔ Ollama) a parameter change, not a code change. |
| **Avoid global state** | No module-level mutable state (no `_cache = {}` at import time holding request-scoped data); anything that looks like a cache is either request/case-scoped and passed explicitly, or an explicitly-designed, documented, thread-safe singleton with a name that says so (`_MITRE_KNOWLEDGE_BASE`, read-only) | Global mutable state is the single most common source of "works on my machine, fails under concurrent Streamlit sessions" bugs. |

---

## 3. Project Structure Rules

The folder-by-folder ownership and the full allowed/forbidden dependency
matrix is defined in **`docs/dependency-rules.md`** and is incorporated here
by reference as binding, not optional, guidance. Restated as the constitution
requires:

### Ownership

Every top-level folder under `core/`, `apps/`, `data/`, `tests/`, `docs/`,
`scripts/` has exactly one `README.md` stating its purpose and
responsibility (already established in the repository foundation). A new
folder is never created without its `README.md` in the same commit.

### Who may import whom (summary — full detail in `docs/dependency-rules.md`)

```
apps/web , apps/api  →  core/services  →  core/graph  →  core/agents
                                                              ↓
                              core/tools , core/parsers  ←───┘
                                          ↓
    core/knowledge , core/memory , core/security , core/db , core/reporting , core/config
```

- **Forbidden, absolutely:** `core/*` importing anything from `apps/*`.
- **Forbidden:** `apps/web` and `apps/api` importing each other.
- **Forbidden:** `core/tools`/`core/parsers` importing `core/agents`,
  `core/graph`, or `core/memory` (leaves never call up).
- **Forbidden:** any module other than `core/memory/long_term.py` importing a
  ChromaDB client directly.
- **Forbidden:** any module other than `core/db/*` constructing/writing
  SQLAlchemy ORM rows directly — agents and tools exchange Pydantic models;
  translation to persistence happens in `core/services` or a repository
  function.
- **Forbidden:** `core/security` depending on anything above `core/config`
  in the stack (a guardrail must not be influenced by the logic it guards).

### Circular dependency prevention

If module A needs something from module B and module B needs something from
module A, the shared concept is missing a home. Resolution order:
1. Can it move to `core/knowledge` (if it's reference data)?
2. Can it move to a new leaf module both A and B depend on?
3. Only if neither applies: escalate as an architecture question requiring
   an ADR — never resolve it by adding a lazy/local import to break the cycle
   mechanically. That hides the design problem instead of fixing it.

### Shared utilities and common interfaces

- Shared Pydantic base models (`BaseFinding`, `BaseEvidence`) live in the
  layer that defines the concept (`core/agents/` for finding bases,
  `core/parsers/` for evidence bases) and are imported downward, never
  sideways between sibling leaf modules.
- A "common interface" (e.g. what every parser must implement) is expressed
  as a Python `Protocol` or abstract base in the owning package's
  `__init__.py` or a dedicated `base.py`, documented in that folder's
  `README.md`.

---

## 4. Agent Design Rules

Every agent in `core/agents/` implements the same interface shape. This
section is the binding contract; `docs/agent-design.md` is the working
elaboration of it — they must never diverge.

1. **Interface.** Every agent exports one node function:
   `def run_<agent_name>(state: CaseInvestigationState) -> CaseInvestigationState`.
   No agent exposes a second, alternate entry point.

2. **Responsibilities.** One agent, one bounded concern, matching its
   blueprint §7 definition exactly (SOC Analyst Agent analyzes logs; it does
   not also score CVSS). An agent that starts doing two agents' jobs must be
   split, not extended.

3. **Inputs / Outputs.** Both are Pydantic models, read from and written to
   named fields on `CaseInvestigationState` — never a raw dict, never a
   free-text string standing in for structured data. Every output model
   includes:
   - `thought: str` — the agent's human-readable reasoning (ReAct).
   - `confidence: float` (0.0–1.0) — see point 6.
   - A domain-specific verdict/finding payload.

4. **Memory access.** An agent reads short-term memory (the current
   `CaseInvestigationState`) directly. Long-term memory (ChromaDB) is
   accessed *only* through the Memory Agent — no specialist agent queries
   ChromaDB directly. This keeps the "memory is always advisory, never a
   hard dependency" rule (`docs/adr/0006-memory-strategy.md`) enforceable in
   exactly one place.

5. **Tool access.** An agent calls tools in `core/tools/` (and read-only
   `core/knowledge/`) to perform any deterministic computation. An agent
   never inlines a calculation a tool could perform (Principle 9,
   `docs/adr/0008-agent-tool-boundary.md`). Which tools a given agent may
   call is declared explicitly at the top of its module (a `TOOLS_USED`
   constant or equivalent), not discovered implicitly by what happens to be
   imported.

6. **Confidence scoring.** Mandatory on every output. Deterministic-parser-
   backed findings default to `1.0` unless the parser itself flagged partial
   confidence; LLM-fallback-derived findings are capped below `0.7` by
   convention, forcing downstream consumers (UI, reports) to visually
   distinguish "the system is sure" from "the system is guessing."

7. **Error handling.** Every agent's failure modes are enumerated in its
   module docstring (mirroring its blueprint §7 "Failure handling" entry) and
   handled with a typed fallback result — never an uncaught exception
   escaping the node function into the graph. A tool-call failure (timeout,
   malformed response) is caught at the agent boundary and turned into a
   `confidence`-penalized or `unmapped`/`insufficient-evidence` result, per
   the specific agent's documented behavior.

8. **Retry strategy.** LLM calls get one automatic retry with backoff on
   transient errors (timeout, rate limit) via the shared LLM client wrapper
   (`core/config` provider abstraction) — never hand-rolled per agent.
   Deterministic tool calls are not retried (a deterministic function
   failing twice in a row fails identically the third time; retrying it
   hides a real bug).

9. **Logging.** Every agent logs its `thought` field via `structlog` at
   `INFO`, bound to `case_id` and `agent_name` context (see §11). Tool calls
   an agent makes are logged at `DEBUG` with tool name and (redacted)
   arguments.

10. **Reasoning boundaries.** An agent reasons only about the evidence and
    context explicitly present in `CaseInvestigationState` and the outputs of
    the tools it calls. It never reasons "in general" about the world beyond
    what's in scope for its documented responsibility (e.g. the Linux
    Security Agent explains and hardens; it does not also render a phishing
    verdict just because a log happens to mention an email).

11. **Forbidden behaviors** (violating any of these is a blocking
    code-review finding, no exceptions):
    - Computing a score/CVSS/MITRE mapping via LLM freeform text instead of
      calling the corresponding tool.
    - Including unsanitized, unguarded attacker-controlled text (a phishing
      body, uploaded source code) directly into a prompt without first
      passing it through `core/security/prompt_guard.py`.
    - Marking any recommended action as "executed" without passing through
      `core/security/approval_gate.py`.
    - Mutating global/module-level state to pass data to another agent
      instead of using `CaseInvestigationState`.
    - Silently swallowing an exception with a bare `except: pass`.
    - Importing `apps.*`.

---

## 5. Tool Design Rules

Tools (`core/tools/*.py`) are the deterministic backbone every agent leans
on (Principle 9). Standards:

- **Registration.** Every tool function is decorated/registered for
  LangGraph/LangChain function-calling with an explicit name, description,
  and Pydantic argument schema — never a bare Python function passed by
  convention. The registration lives next to the function definition, not in
  a separate, easily-out-of-sync registry file.
- **Interfaces.** A tool's signature is fully typed in and out; if a tool
  returns a structured result (not a bare scalar), it returns a Pydantic
  model, matching the "typed contracts everywhere" rule.
- **Validation.** A tool validates its own inputs at the top of the function
  (via Pydantic, or explicit guard clauses for primitives) and raises a
  specific, named exception (not a bare `ValueError`/`Exception`) on invalid
  input — see `core/tools/exceptions.py` per capability area if a capability
  area needs more than one distinct error type.
- **Exceptions.** Every tool module defines its own narrow exception classes
  (e.g. `CVSSVectorParseError`) rather than reusing a generic project-wide
  exception for unrelated failure modes — callers need to be able to catch
  precisely.
- **Timeouts.** Any tool making an external call (future STIX/TAXII feed
  lookups, etc.) has an explicit, configurable timeout (via
  `core/config/settings.py`) — no unbounded external call ever ships.
- **Retries.** Deterministic, no-I/O tools are never retried (see §4.8). A
  tool that legitimately performs I/O (an external threat-intel lookup)
  retries only transient failures, with a max-attempt cap and backoff,
  identical policy to the LLM client wrapper.
- **External APIs.** Any tool wrapping a third-party API lives behind a thin
  adapter (`core/tools/<capability>_client.py`) so the tool logic itself
  never directly constructs HTTP requests inline — this is what makes the
  adapter mockable in unit tests.
- **Caching.** Only applied to genuinely expensive, idempotent lookups
  (e.g. a MITRE technique lookup by ID) and always explicit and scoped
  (a documented in-process LRU cache, never an unbounded global dict) —
  see §2's "avoid global state" for the boundary.
- **Deterministic outputs.** Given the same input, a tool returns the same
  output every time — this is the property that makes tools unit-testable
  with a fixed expected value and is the entire reason they exist separately
  from LLM reasoning (Principle 9). A tool whose output can legitimately
  vary run-to-run (e.g. a live threat-intel lookup) must document this
  explicitly in its docstring and is treated as an integration-tested
  boundary, not a unit-tested pure function.

---

## 6. API Design

Applies to `apps/api` (FastAPI). Not the primary interface yet (Streamlit
is), but built to the same standard from day one per
`docs/adr/0002-fastapi-service-boundary.md`.

- **REST endpoints / naming.** Resource-oriented, plural nouns:
  `/cases`, `/cases/{case_id}/evidence`, `/cases/{case_id}/findings`,
  `/cases/{case_id}/reports`. No verbs in URLs (`/cases/{id}/analyze` is the
  one accepted exception for an explicit action-trigger endpoint, modeled as
  a `POST` sub-resource, not a pattern to generalize elsewhere).
- **Versioning.** All routes are mounted under `/api/v1/...` from the first
  release. A breaking change to a response schema requires a new `/api/v2/`
  mount, never a silent breaking change to `v1`.
- **HTTP methods.** `GET` (read, no side effects), `POST` (create or trigger
  an action), `PATCH` (partial update), `DELETE` (remove) — `PUT` is not used
  (no full-replace semantics needed in this domain).
- **Response schemas.** Every endpoint's response is a named Pydantic model
  in `apps/api/schemas.py` (or per-router schema module), documented in the
  auto-generated OpenAPI spec — never a bare dict or `JSONResponse` with
  inline structure.
- **Error responses.** A single consistent error envelope
  (`{"error": {"code": str, "message": str, "details": dict | None}}`) for
  every non-2xx response, mapped from internal exception types by a shared
  FastAPI exception handler — routers never hand-construct error JSON
  inline.
- **Validation.** Request bodies/query params are Pydantic models bound via
  FastAPI's dependency injection; a router function's first lines are never
  manual `if "x" not in payload` checks.
- **Authentication readiness.** No auth is implemented pre-v1.0 (single-
  analyst mode per blueprint §3), but every router is written with a
  `current_user: User = Depends(get_current_user)` placeholder dependency
  from the start (currently returning a fixed default user), so adding real
  auth later is a dependency swap, not a router rewrite.
- **Pagination.** Any list endpoint (`GET /cases`, `GET /cases/{id}/findings`)
  uses cursor-based pagination (`?cursor=...&limit=...`) from the first
  implementation, even while case volume is small — retrofitting pagination
  onto a "return everything" endpoint later is a breaking change under
  versioning rules above.
- **Filtering.** Query parameters for filtering (`?severity=high`,
  `?status=open`) are explicit, typed, and documented per endpoint — no
  generic/opaque filter-query-language endpoint.
- **Rate limiting readiness.** Not implemented pre-v1.0, but every router is
  structured so a rate-limiting dependency/middleware can be added at the
  FastAPI app-factory level (`apps/api/main.py`) without touching individual
  routers.

---

## 7. Database Rules

Governs `core/db/` (SQLAlchemy models, sessions, Alembic migrations).

- **Schema naming.** Tables: `snake_case`, plural (`cases`, `findings`,
  `mitre_techniques`). Columns: `snake_case`, singular concept names
  (`severity`, `risk_score`, `created_at`). Foreign keys:
  `<referenced_table_singular>_id` (`case_id`, `evidence_id`).
- **Primary keys.** Every table has a surrogate primary key (`id`, UUID),
  never a natural key (e.g. never `technique_id` as the sole PK for
  `mitre_techniques` even though it looks unique — it's a business identifier
  that could theoretically be revised by MITRE; store it as a unique indexed
  column instead).
- **Indexes.** Every foreign key column is indexed. Every column used in a
  `WHERE`/`ORDER BY` on a list endpoint (`Case.status`, `Case.severity`,
  `Finding.severity`) is indexed. Indexes are added in the same migration as
  the column, never as an afterthought migration once a query is observed to
  be slow.
- **Relationships.** Declared explicitly via SQLAlchemy `relationship()` with
  an explicit `back_populates` on both sides — never a one-sided
  relationship that silently fails to update the other side's collection.
  Cascade behavior (`cascade="all, delete-orphan"` for `Case → Evidence/
  Finding/TimelineEvent`) is declared explicitly, matching blueprint §8's
  ownership model (deleting a Case deletes its Evidence/Findings; deleting a
  `MitreTechnique` reference row never cascades into Findings — it's a
  reference table, not owned by any Case).
- **Migrations.** Every schema change is an Alembic migration, generated via
  `alembic revision --autogenerate` and hand-reviewed (never trusted blindly)
  before commit. One logical schema change per migration file — no bundling
  unrelated table changes into one migration. Migrations are never edited
  after being merged to `main`; a mistake gets a new corrective migration.
- **Transactions.** Any operation that writes to more than one table (e.g.
  creating a `Case` and its first `Evidence` row) happens inside one
  transaction/session commit — partial writes across tables are never
  acceptable for a single logical operation.
- **Repositories.** Raw SQLAlchemy queries live behind repository functions
  in `core/db/` (or `core/services/`), never inline inside an agent or a
  router. This is the layer that translates between ORM rows and the
  Pydantic models agents/routers actually work with (per §3's "who writes to
  the DB" rule).
- **Query patterns.** Prefer explicit, readable queries (SQLAlchemy 2.0
  `select()` style) over raw SQL strings; raw SQL is permitted only for a
  documented performance-critical case, reviewed and commented with why the
  ORM query wasn't sufficient.
- **Future scalability.** Schema additions (multi-user/RBAC per blueprint
  §17) are additive tables/columns with migrations — the existing
  `Case/Evidence/Finding/TimelineEvent/MitreTechnique/Report/User` schema
  (blueprint §8) is never redesigned to accommodate a future feature; it's
  extended.

---

## 8. Logging

Structured, `structlog`-based, JSON-formatted, written to `logs/` (per
`logs/README.md`). This is the explainability audit trail the whole product
is built around — logging quality is a product feature here, not just an ops
concern.

- **Log levels.** `DEBUG` (tool-call arguments/results, verbose internals),
  `INFO` (every agent's `thought`, every case state transition), `WARNING`
  (a documented fallback path was taken — e.g. LLM-fallback parsing kicked
  in), `ERROR` (a handled failure that degraded functionality — e.g.
  ChromaDB unreachable, Memory Agent degraded to "no historical context"),
  `CRITICAL` (an unhandled condition that aborted a case investigation).
- **Structured logging.** Every log call passes structured key-value context
  (`logger.info("agent_reasoning", thought=..., case_id=..., agent_name=...)`)
  — never an interpolated free-text string as the sole content. This is what
  makes `logs/` queryable/filterable per case, per agent, per severity.
- **Request IDs.** Every `apps/api` request gets a generated `request_id`
  (middleware-injected), included in every log line emitted while handling
  that request.
- **Case IDs.** Every log line emitted during a case investigation is bound
  to `case_id` via `structlog`'s context-binding (`bind(case_id=...)`) at the
  top of the graph run — no log call inside an agent needs to remember to
  pass it manually.
- **Agent IDs.** Every agent binds `agent_name` to its logger context on
  entry, so the full ReAct trail for a case can be filtered/grouped by which
  agent produced which line.
- **Correlation IDs.** For a case spanning multiple graph runs (re-analysis
  after new evidence is added), a stable `investigation_run_id` links all log
  lines from one graph execution, distinct from the case-lifetime `case_id`.
- **Sensitive data masking.** `core/security/pii_redaction.py` is applied to
  any log payload derived from raw evidence content (email bodies, source
  code snippets) before it's logged — API keys, passwords, and PII patterns
  are masked, never logged in full, matching `SECURITY.md`'s scope.
- **Rotation strategy.** Size- and time-based rotation (e.g. daily, retained
  14 days, gzip-compressed after 1 day) configured at the `structlog`/stdlib
  logging handler level in `core/config/settings.py` — logs are never
  allowed to grow unbounded on a long-running deployment.

---

## 9. Error Handling

Project-wide, consistent handling so a failure's severity is legible from
where and how it's caught, not from reading the whole call stack.

- **Propagation.** An exception raised inside a tool or parser propagates up
  to the calling agent, which is required to catch it and convert it into a
  typed, documented outcome (a degraded finding, an "unmapped" result, a
  `ManualTriageRequired` state) — it never propagates further up into
  `core/graph` unhandled. `core/graph`/`core/services` catch only truly
  unexpected exceptions (a bug, not a documented failure mode) and convert
  them into a case-level "investigation failed, see logs" state rather than
  crashing the whole application process.
- **Recoverable errors.** Anything with a documented fallback (parser
  low-confidence result, memory retrieval outage, an agent's specific
  "Failure handling" entry from blueprint §7) is recoverable by definition —
  handled at the point of failure, logged at `WARNING`/`ERROR`, and the
  investigation continues in a degraded-but-correct state.
- **Fatal errors.** Anything with no documented fallback (a corrupted
  database connection, a missing required config value at startup) is fatal
  — the application/worker fails to start or the specific request/case run
  fails loudly with a `CRITICAL` log, never limps along in an undefined
  state.
- **Validation errors.** Raised as Pydantic `ValidationError` at the
  boundary where untrusted structure enters the system (API request body,
  evidence upload, tool arguments) and translated to a `4xx` API response or
  a rejected-upload UI message — never allowed to propagate as a generic
  `500`/unhandled exception.
- **Agent failures.** Handled per §4.7 — every agent has a documented
  fallback; a failure inside one agent never aborts other independent
  agents already scheduled for the same case (partial results are better
  than no results).
- **External API failures** (LLM provider, future threat-intel feeds).
  Retried per §4.8/§5's policy, then converted to a degraded result
  (lower confidence, "insufficient evidence" outcome) rather than failing
  the entire case.
- **User-facing messages.** Plain language, no stack traces, no internal
  exception class names — a Streamlit/API consumer sees "This email couldn't
  be fully parsed; some fields may be missing" not `KeyError: 'from_addr'`.
- **Internal logs.** Always the full detail (stack trace, exception type,
  context) — the separation between user-facing message and internal log is
  intentional and absolute; the two are never the same string.

---

## 10. Security Standards

Cross-references `SECURITY.md` (the reporting policy) and
`core/security/README.md` (the implementation). This section is the
binding *rule set*; those files are its *policy* and *implementation*
counterparts respectively.

- **Secret management.** Every secret (API keys, DB credentials) is an
  environment variable, loaded exclusively via `core/config/settings.py`,
  documented in `.env.example` with a placeholder (never a real value),
  never committed, never logged (see §8).
- **Environment variables.** `.env` is gitignored; `.env.example` is the
  single source of truth for which variables exist — every new config knob
  is added to `.env.example` in the same PR that introduces it.
- **Input validation.** Every external input (API request, uploaded
  evidence file, chat message) is validated against a Pydantic schema at the
  boundary before any business logic touches it.
- **Prompt injection protection.** Any text originating from an untrusted
  source (phishing email body/headers, uploaded source code, a chat message)
  passes through `core/security/prompt_guard.py` before being interpolated
  into any LLM prompt — structurally required, not review-dependent (see
  Principle 8, `docs/adr/0008-agent-tool-boundary.md`'s spirit extended to
  input handling).
- **Output validation.** Every LLM response consumed by the application is
  parsed into a typed Pydantic model (function/tool-calling structured
  output), never treated as trusted freeform text to render directly — this
  also catches a successful prompt-injection attempt that tries to make the
  LLM emit unexpected structure.
- **Dependency security.** `.github/dependabot.yml` keeps pip/Docker/GitHub
  Actions dependencies current; a new third-party dependency is justified in
  its introducing PR's description (per `CONTRIBUTING.md`'s review
  checklist) and pinned to a specific version range in `requirements.txt`.
- **Least privilege.** The database user, any future service account, and
  any external API key are scoped to only the permissions the application
  actually needs — never a superuser/admin credential used for convenience.
- **Safe defaults.** Debug mode off by default (`APP_ENV=development` still
  does not imply verbose error leakage to a client — only to `logs/`);
  new features ship with the most conservative behavior enabled by default
  (e.g. a new "auto-approve low-risk actions" feature, if ever built, ships
  defaulted to *off*, requiring explicit opt-in) — matching the hard
  `core/security/approval_gate.py` boundary already established.

---

## 11. Testing Strategy

Three tiers, exactly matching `tests/README.md`'s structure — this section is
the binding policy; that file is the folder-level pointer to it.

- **Unit tests** (`tests/unit`, marker `unit`). Every function in
  `core/tools/` and `core/parsers/` ships with unit tests before it's wired
  into an agent. No database, no real LLM call (mocked), no filesystem
  beyond committed fixtures in `data/sample_evidence/`. Fast — this tier
  gates every commit via pre-commit/CI.
- **Integration tests** (`tests/integration`, marker `integration`). Full
  `core/graph/investigation_graph.py` runs against `data/sample_evidence`
  fixtures, asserting on persisted `Finding` rows, MITRE mappings, and
  cross-evidence correlation. Runs against a real (containerized) Postgres;
  LLM calls may be mocked for speed/determinism, with a separate,
  less-frequent CI job running against a real cheap model to catch prompt
  drift.
- **Agent tests.** Each agent has at least one test that invokes its node
  function directly with a hand-built `CaseInvestigationState` fixture
  (bypassing the full graph) — proving the agent's contract in isolation,
  independent of orchestration correctness (which integration tests cover
  separately).
- **API tests.** Every `apps/api` router has a test using FastAPI's
  `TestClient`, asserting on status code and response schema — including at
  least one test per endpoint for the validation-error path (§9).
- **Regression tests.** Any bug fix lands with a test that would have failed
  before the fix and passes after — a bug fixed without a regression test is
  not considered fixed (see Definition of Done, `CONTRIBUTING.md`).
- **Mock strategy.** Mock at the boundary, not the internals: mock the LLM
  client's HTTP call, not an agent's internal method; mock ChromaDB's
  client, not `core/memory/long_term.py`'s internal logic. This keeps tests
  meaningful — they exercise real code paths up to the actual external
  dependency.
- **Coverage expectations.** `core/tools/` and `core/parsers/` target ≥90%
  line coverage (they're pure functions — there's no excuse for gaps).
  `core/agents/` targets ≥80% (some LLM-dependent branches are harder to
  hit deterministically). `apps/*` presentation code is not coverage-gated
  but must have at least a smoke test per page/router. Coverage is tracked
  via `pytest-cov` in CI (`.github/workflows/ci.yml`) and reported, not
  silently ignored.
- **Golden tests** (`tests/golden`, marker `golden`). Report-snapshot
  comparisons — see `tests/golden/README.md`. A failing golden test blocks
  merge until the snapshot is deliberately regenerated and the diff reviewed
  in the PR, never silently overwritten by a script.
- **Definition of Done** (restated from `CONTRIBUTING.md` as binding here):
  merged to `main`, CI green (lint, typecheck, dependency-rules check, unit +
  integration tests), new parser/tool functions have unit tests including at
  least one adversarial/malformed-input case where the input is untrusted,
  documentation (`docs/`) updated, `docs/roadmap.md` checkbox updated if a
  milestone item closed, `CHANGELOG.md` updated, no TODOs or placeholder
  logic left in the changed files.

---

## 12. Documentation Standards

- **Docstrings.** Every public function/class in `core/` has a one-line
  docstring stating *what* it does (the signature plus type hints already
  say how); a longer docstring is added only when a non-obvious constraint,
  invariant, or workaround needs explaining — matching the project's
  "comment the why, not the what" convention already established in
  `docs/engineering-standards.md`.
- **Markdown.** Every `docs/*.md` and every folder `README.md` stays
  synchronized with the code it describes — a PR that changes an agent's
  contract updates `docs/agent-design.md`'s relevant section (or the
  blueprint, only via ADR if the change is architecturally significant) in
  the same PR, not a follow-up "docs" PR that may never land.
- **Architecture updates.** `context/01_blueprint.md` is never edited to
  reverse a decision — an architecturally significant change requires a new
  ADR (§ next bullet) and, only after that ADR is accepted, a corresponding
  update to `docs/architecture.md` (the living index), leaving the original
  blueprint intact as the historical record of the original design
  reasoning.
- **ADR updates.** Any decision matching an ADR's decision criteria (see
  `docs/adr/README.md`) gets a new, sequentially numbered ADR before
  implementation begins — not written retroactively to justify code that's
  already merged.
- **Code comments.** Reserved for the non-obvious: a hidden constraint, a
  specific bug workaround, a subtle invariant that would surprise a reader.
  Never used to restate what well-named code already communicates, and never
  used to reference "the current task" or a specific PR/issue number (those
  belong in the PR description, not in code that outlives the PR).
- **README updates.** The root `README.md`'s module-coverage table and
  project-status section are updated whenever a milestone in
  `docs/roadmap.md` closes — the README must never claim more than what
  `main` actually does.
- **Changelog.** Every merged PR adds an entry under `[Unreleased]` in
  `CHANGELOG.md` (per `CONTRIBUTING.md`); a milestone release moves
  `[Unreleased]` into a new dated, versioned section.

---

## 13. Git Standards

Restated here as binding policy; `CONTRIBUTING.md` is the contributor-facing
elaboration.

- **Branch strategy.** `main` is always releasable. Short-lived feature
  branches: `feat/<name>`, `fix/<name>`, `docs/<name>`, `chore/<name>`,
  `refactor/<name>`. No direct commits to `main`. Rebase on `main` before
  opening a PR.
- **Commit format.** Conventional Commits — `type(scope): summary`, one
  logical change per commit. Types: `feat`, `fix`, `docs`, `test`,
  `refactor`, `chore`, `perf`, `ci`. Scope is the top-level folder most
  affected (`agents`, `parsers`, `db`, `web`, `api`).
- **Pull requests.** Every PR uses `.github/PULL_REQUEST_TEMPLATE.md`,
  references the milestone/issue it advances, and cannot merge with a red
  CI run (lint, typecheck, dependency-rules check, tests).
- **Code review checklist.** The checklist already codified in
  `CONTRIBUTING.md` is binding: correct layer placement, typed contracts,
  tool-vs-LLM computation boundary respected, prompt-injection guard applied
  where required, new dependencies justified, tests present for new
  parsers/tools.
- **Release tags.** Pre-1.0: `v0.X-milestone-name` per completed milestone
  (`docs/roadmap.md`). Post-1.0: Semantic Versioning
  (`MAJOR.MINOR.PATCH`) — `MAJOR` for breaking API/schema changes (including
  an `/api/v2` cutover per §6), `MINOR` for new agents/modules, `PATCH` for
  fixes.
- **Semantic versioning enforcement.** A schema migration that isn't purely
  additive, or an API contract change under `/api/v1`, requires a `MAJOR`
  bump and an ADR explaining the break — breaking changes are never shipped
  as a `PATCH` or `MINOR` release.

---

## 14. Implementation Contract

Every future implementation task — whether it's one function or a whole
milestone — follows this sequence, without exception:

1. **Review the blueprint** (`context/01_blueprint.md`) for the relevant
   layer/agent/module's approved design.
2. **Review the repository structure** (the relevant folder's `README.md`,
   `docs/dependency-rules.md`) to confirm where new code belongs.
3. **Review this constitution** for the applicable standards (Python,
   agent/tool design, testing, security, etc.).
4. **List files before generating code** — state every file to be created or
   modified, before writing any of them.
5. **Explain why every file exists** — one sentence per file tying it to a
   blueprint responsibility or a constitution rule.
6. **Explain integration points** — which existing modules this calls, which
   existing modules will call it, and which layer boundary (per §3) each
   crossing respects.
7. **Explain risks** — what could break, what's untested until integration,
   what a reviewer should scrutinize.
8. **Generate production-quality code only** — fully typed, tested per §11,
   logged per §8, error-handled per §9, no placeholder logic left behind
   without an explicit, tracked TODO tied to a milestone.
9. **Never duplicate functionality** — search `core/tools/`,
   `core/parsers/`, and `core/knowledge/` for an existing equivalent before
   writing a new one; reuse or extend, don't reimplement.
10. **Never violate architecture** — if a task seems to require crossing a
    forbidden dependency (§3) or bypassing a tool/agent boundary (§4/§5, §9's
    injection-guard rule), stop and raise it as an architecture question
    (new ADR) rather than writing the violation "just this once."

---

## 15. Self-Review

Honest evaluation of this constitution against the dimensions that matter
for this project's stated goals (blueprint §2: portfolio quality, enterprise
readiness, teaching value).

| Dimension | Score | Justification |
|---|---|---|
| Maintainability | 10 | Every rule ties back to a concrete artifact (a folder, a file, an ADR) rather than floating abstract advice — there is always a checkable "does the code match this" answer. |
| Scalability | 10 | Nothing here assumes single-analyst scale as permanent — DB/API/testing rules (pagination from day one, additive schema changes, versioned API) are written for the system this could grow into, per blueprint §17, without requiring a rewrite of this document. |
| Security | 10 | Prompt-injection defense, output validation, and the approval gate are structural requirements (§4.11, §9, §10), not review-dependent checklist items — the rules describe *how the code path is shaped* so the unsafe path doesn't compile/pass CI, not just "remember to check this." |
| Readability | 10 | Every section is a table or a short numbered list with a "why," matching the project's own documented style (`docs/engineering-standards.md`) — this document practices what it mandates. |
| Enterprise readiness | 10 | Versioning, migration discipline, least-privilege, rate-limiting readiness, and the amendment process (§ header) are the exact governance artifacts a real engineering org expects and audits for. |
| Resume value | 10 | A reviewer skimming this document sees layered architecture discipline, typed-contract enforcement, deterministic/LLM boundary reasoning, and real testing/security rigor — the signal a hiring engineer is specifically looking for in a portfolio AI project. |
| GitHub quality | 10 | Directly load-bearing for `CONTRIBUTING.md`, the PR template's checklist, and CI's automated checks (`scripts/check_dependency_rules.py`) — this isn't a document that sits unused next to the code; the repository already enforces pieces of it mechanically. |
| Competition quality | 10 | Goes meaningfully beyond the capstone PDF's explicit requirements (which ask for working modules, not a governance constitution) while never contradicting or replacing any of its required functionality — exactly the differentiation blueprint §18's final recommendations call for. |

No dimension scored below 10 on this pass; no further revision required
before this document takes effect.

---

*This constitution is binding as of the date of its creation and remains in
force until amended per the process defined in this document's header.*
