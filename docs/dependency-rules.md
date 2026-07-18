# Dependency Rules

Strict, enforced rules for which layers may import from which. Violating
these is a blocking code-review finding and, where mechanically checkable, a
CI failure (`scripts/check_dependency_rules.py`, run via pre-commit and CI).

## The layer stack (import direction flows one way: top → down only)

```
apps/web , apps/api            (frontends — presentation only)
        ↓ may import
core/services                  (orchestration for frontends)
        ↓ may import
core/graph                     (LangGraph workflow)
        ↓ may import
core/agents                    (specialist agents)
        ↓ may import
core/tools , core/parsers       (deterministic functions)
        ↓ may import
core/knowledge , core/memory , core/security , core/db , core/reporting , core/config
        (leaf layers — import each other sparingly and only where documented below)
```

## Rules

1. **`core/` never imports from `apps/`.** No exceptions. This is the rule
   that keeps `core/` framework-agnostic and testable headlessly. Enforced by
   `scripts/check_dependency_rules.py` (static import scan) in CI.

2. **`apps/web` and `apps/api` never import each other.** Both are
   independent front doors to `core/services`; if they need to share logic,
   that logic belongs in `core/services`, not in one importing from the other.

3. **`apps/web` pages/components and `apps/api` routers contain no business
   logic.** They validate/render and call exactly one `core/services`
   function per user action. If you find yourself writing an `if` statement
   that makes a security/business decision inside a Streamlit page or a
   FastAPI router, that logic belongs in `core/services` or below.

4. **`core/agents` may import `core/tools`, `core/parsers`, `core/knowledge`,
   `core/memory`, `core/security`, and — as the one explicit exception to
   "leaves never call up" — `core/graph/state.py` specifically (not
   `core/graph/investigation_graph.py`, `routing.py`/`router.py`, or
   `workflow_engine.py`). `CaseInvestigationState` is a shared leaf
   *contract*, not graph business logic: constitution §4.1 mandates every
   agent's literal signature be `(state: CaseInvestigationState) -> CaseInvestigationState`,
   which is impossible to type without importing it. Treat
   `core/graph/state.py` as belonging to the same "shared contract" leaf
   category as the root-level `core/exceptions.py`, `core/schemas.py`,
   `core/interfaces.py` (see `docs/adr/0009-multi-agent-framework-shape.md`
   point 7). Agents never import `core/db` directly — persistence happens
   through `core/services` or a repository function `core/graph` calls,
   keeping agents unaware of SQL/ORM details.

5. **`core/tools` and `core/parsers` may import `core/knowledge`** (e.g. a
   tool interpreting a CVSS vector uses `core/knowledge/cvss_calculator.py`)
   **but never `core/agents`, `core/graph`, or `core/memory`.** Tools/parsers
   are leaves — nothing calls up from them, and they call nothing above them.

6. **`core/memory` is the only layer allowed to import a vector-store client
   (ChromaDB).** No other layer talks to ChromaDB directly.

7. **`core/db` is the only layer allowed to import SQLAlchemy models
   directly for writes.** Agents and tools receive/return Pydantic models;
   translation to/from ORM rows happens in `core/services` or a dedicated
   repository function, never inline in an agent.

8. **`core/security` has no outbound dependency on any other `core/`
   subpackage** other than `core/config` (for pattern-list overrides). It is
   called *by* agents and services, never the reverse — a guardrail that
   itself depends on business logic could be bypassed by that logic changing.

9. **`core/config` is a leaf with zero internal dependencies.** Every other
   module may depend on it; it depends on nothing in `core/` or `apps/`.

10. **No circular imports, period.** If two modules seem to need each other,
    the shared concept is missing a home — extract it to `core/knowledge` (if
    it's data/reference) or introduce a new leaf module, don't create a cycle.

## Why this shape

- **Testability:** every layer below `core/services` is unit-testable with
  no database, no HTTP server, no browser.
- **Swappability:** the frontend (rule 2) and the persistence technology
  (rule 7) can each change without touching agent logic.
- **Auditability:** security guardrails (rule 8) can't be silently
  circumvented by a change elsewhere in the dependency graph, because nothing
  they depend on can be manipulated by the code they're guarding.

## Enforcement

`scripts/check_dependency_rules.py` statically scans `core/**/*.py` import
statements and fails if any module imports `streamlit`, `fastapi`, or a
sibling `core/` subpackage outside the allowed edges above. Wired into
`.pre-commit-config.yaml` and `.github/workflows/ci.yml`.
