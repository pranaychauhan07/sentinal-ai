# Engineering Standards

Project-wide rules. CI enforces what's mechanically enforceable (ruff, mypy,
`scripts/check_dependency_rules.py`); the rest is enforced at code review
(see the checklist in `CONTRIBUTING.md`).

## Naming conventions

- **Modules/files:** `snake_case.py` (`soc_analyst_agent.py`, `nmap_parser.py`).
- **Classes / Pydantic models:** `PascalCase` (`NormalizedEvidence`,
  `PhishingVerdict`). Every agent's output model name ends in a noun that
  describes the result, not the agent (`ThreatHuntingReport`, not
  `ThreatHuntingAgentOutput`).
- **Functions:** `snake_case`, verb-first (`parse_email`, `calculate_cvss`,
  `detect_bruteforce_pattern`).
- **LangGraph node functions:** always named `run_<agent_name>` for
  discoverability (`run_soc_analyst_agent`).
- **Tests:** `test_<module_under_test>.py`, one test file per source file in
  `core/parsers` and `core/tools`.
- **Streamlit pages:** numeric-prefixed to control sidebar order
  (`1_Case_Dashboard.py`).

## Folder conventions

- `core/` has no knowledge of `apps/` — see `docs/dependency-rules.md`.
- Every folder has a `README.md` explaining purpose/responsibility (this repo
  is the reference example — see any existing folder).
- Test tier mirrors source layout: a change in `core/tools/vuln_tools.py`
  pairs with `tests/unit/test_vuln_tools.py`.

## Import conventions

- Absolute imports only (`from core.tools import scoring`), never relative
  imports crossing package boundaries.
- Import order enforced by ruff's isort rules (`pyproject.toml`
  `[tool.ruff.lint.isort]`): stdlib → third-party → first-party (`core`,
  `apps`).
- No wildcard imports (`from x import *`) anywhere.

## Type hinting

- Every function in `core/` has full type hints on parameters and return
  value; mypy runs in `disallow_untyped_defs` mode for `core.*`
  (`pyproject.toml`). `apps/*` is relaxed since it's presentation glue.
- Prefer Pydantic models over `TypedDict`/`dict[str, Any]` for any structure
  that crosses a function boundary more than once.

## Docstrings and comments

- Public functions/classes in `core/` get a one-line docstring stating what
  they do (not how) — see the root CLAUDE-style guidance: default to no
  inline comments; add one only when the *why* isn't obvious from the code
  (a non-obvious constraint, a workaround, a subtle invariant).
- Never leave commented-out code in a merged PR.

## Logging

- Use `structlog` exclusively — no bare `print()` in `core/` or `apps/`.
- Every agent logs its `Thought` field at `INFO` level under a
  `case_id`-bound logger context so a full case's reasoning trail can be
  filtered from `logs/`.
- Never log secrets, API keys, or full PII — see `core/security/pii_redaction.py`.

## Error handling

- Parsers never raise on malformed input for a single evidence item — they
  return a low-confidence result with `unparsed_fragments` populated (see
  `docs/agent-design.md`).
- Agents catch and classify tool/LLM failures into a documented fallback
  state (per blueprint §7's per-agent "Failure handling") rather than letting
  exceptions propagate out of a LangGraph node.
- Only the outermost service/route layer (`core/services`, `apps/api`
  routers) is allowed to translate an exception into a user-facing error
  message.

## Code formatting

- `ruff format` is the single source of truth for style; do not hand-format
  against it. Line length 100 (`pyproject.toml`).
- Run `make format` before committing; pre-commit re-runs it automatically.

## Testing strategy

- **Unit** (`tests/unit`): every parser and every tool function — pure, fast,
  no network/DB.
- **Integration** (`tests/integration`): full graph runs against
  `data/sample_evidence` fixtures, asserting on persisted `Finding` rows.
- **Golden** (`tests/golden`): report-snapshot tests; regenerated deliberately
  and reviewed in the PR diff, never silently overwritten.
- Any parser/agent touching untrusted input (phishing bodies, uploaded
  source, malformed XML/CSV) requires at least one adversarial/malformed-
  input test.

## Commit message conventions

Conventional Commits — see `CONTRIBUTING.md` for the full spec and examples.

## Branch strategy

Short-lived feature branches off `main`, rebased before PR, squash-merged
with a Conventional-Commit-formatted final message — see `CONTRIBUTING.md`.

## Pull request requirements / Definition of Done / Code review checklist

See `CONTRIBUTING.md` — kept in one place to avoid the two documents
drifting out of sync.
