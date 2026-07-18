# ADR-0006: Memory Strategy — Short-Term State vs. Long-Term Retrieval

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

"Shared memory" spans two very different needs: passing data between agents
*within one case's investigation run*, and learning *across* cases over time.
Conflating these into one mechanism would either make the in-run state
unnecessarily slow (going through a vector store for every agent handoff) or
make cross-case learning impossible (if state were purely in-memory and
discarded at case close).

## Decision

Two explicitly separate mechanisms:

- **Short-term memory** (`core/memory/short_term.py`): the `CaseInvestigationState`
  object itself, scoped to one graph run, holding the current case's evidence
  and findings-so-far. Not persisted independently — it's the LangGraph state.
- **Long-term memory** (`core/memory/long_term.py`): ChromaDB-backed retrieval
  across *closed* cases, read at the start of a new investigation (Memory
  Agent, read path) and written at case close (Memory Agent, write path).
  Always advisory — see ADR-0005.

See `context/01_blueprint.md` §7 (Memory Agent), §9 (data flow steps 4 and 11).

## Alternatives Considered

- **Single unified memory (everything through ChromaDB)** — would make every
  intra-case agent handoff dependent on vector-store latency/availability,
  turning an optional capability into a hard dependency for basic
  functionality. Rejected.
- **No long-term memory in v1, add later** — simpler initially, but the PDF's
  Project 9 explicitly names shared memory as a required capability, and
  retrofitting write-paths into every agent after the fact is more invasive
  than building the read/write hooks in from the Coordinator/Memory Agent
  boundary from the start (M6, per `docs/roadmap.md`).

## Consequences

- **Positive:** intra-case agent communication is fast and has zero external
  dependency; cross-case learning is additive and optional, matching the
  "advisory only" failure-handling rule everywhere else in the memory layer.
- **Negative:** two distinct code paths under `core/memory/` to reason about
  — mitigated by the clear read-at-start/write-at-close boundary documented
  here and in `docs/threat-pipeline.md`.
