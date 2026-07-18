# Developer Guide

Assumes you've completed `docs/setup-guide.md`. This covers how to work in
the codebase day to day.

## Mental model

- `core/` is the product. It has zero knowledge of Streamlit or FastAPI.
- `apps/web` and `apps/api` are two interchangeable front doors that call
  `core/services/*`.
- Everything in `core/` flows through the pipeline in
  `docs/threat-pipeline.md`, orchestrated by `core/graph/investigation_graph.py`.

Read `docs/architecture.md` and `docs/dependency-rules.md` before your first
non-trivial change.

## Adding a new evidence type

1. Add a parser: `core/parsers/<format>_parser.py`, returning a typed
   `NormalizedEvidence` subtype. Unit test it in `tests/unit/` against a
   fixture you add to `data/sample_evidence/`, including at least one
   malformed/adversarial fixture.
2. If it needs a new specialist agent, follow `docs/agent-design.md` →
   "Adding a new agent."
3. Wire evidence-type detection into the Coordinator's classification step
   (blueprint §7, Coordinator Agent).
4. Add an integration test in `tests/integration/` that runs a full case with
   this evidence type through the graph.

## Adding a new tool

Tools (`core/tools/*.py`) are plain, deterministic Python functions — no LLM
calls inside a tool, ever (see `docs/adr/0008-agent-tool-boundary.md`). Every
tool ships with unit tests before any agent calls it.

## Working with the LangGraph state

`core/graph/state.py`'s `CaseInvestigationState` is the only channel data
moves through during an investigation run. Never introduce a global/module-
level variable to pass data between agents — if two agents need to share
something, it goes on the state object.

## Running a single agent in isolation

Each agent module exports a plain node function; you can call it directly in
a Python shell/test with a hand-built `CaseInvestigationState` fixture without
spinning up the full graph — useful while developing a new agent before it's
wired in.

## Logging and the Investigation Trail

Every agent's `Thought` field is logged via `structlog` (JSON, to `logs/`) and
surfaced in the Streamlit "Investigation Trail" panel. When debugging, prefer
reading the structured log over adding print statements — the log already
captures the ReAct Thought → Action → Observation sequence per case.

## Before opening a PR

Run `make lint`, `make typecheck`, `make test` locally — CI runs the same
three, plus `scripts/check_dependency_rules.py`. See `CONTRIBUTING.md` for the
full PR checklist and Definition of Done.
