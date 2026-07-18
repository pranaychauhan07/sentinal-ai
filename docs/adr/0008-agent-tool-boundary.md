# ADR-0008: Strict Agent/Tool Boundary (Deterministic Math Is Never LLM Math)

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

LLMs are unreliable at exact arithmetic (CVSS vector scoring, weighted risk
scoring, MITRE technique lookups) and reports that get these numbers wrong
undermine the entire tool's credibility as a SOC instrument. We needed a firm
rule about where computation happens before implementing any agent.

## Decision

Every deterministic calculation is a plain Python function in `core/tools/`
(or `core/knowledge/cvss_calculator.py`), unit tested, and called by an agent
via LangGraph's function/tool-calling mechanism. An agent's role is strictly
to decide *which* tool to call and *how to interpret/present* the result — it
never performs the calculation itself inside its own reasoning/generation.
See `context/01_blueprint.md` §7, §11 ("Function/Tool Calling"), and
`docs/agent-design.md` point 3.

## Alternatives Considered

- **Let the LLM compute scores directly in its response** — simplest to
  prompt for, but non-deterministic (the same finding could get a different
  score on two runs) and unverifiable without re-deriving the math by hand
  every time; unacceptable for a system whose whole value proposition is
  trustworthy triage.
- **Post-hoc validation (let the LLM compute, then check the number)** —
  still requires the deterministic function to exist for validation, so it
  saves nothing over just using that function to compute the number in the
  first place, while adding a discard-and-retry path for wrong answers.

## Consequences

- **Positive:** every score in the system is reproducible, unit-testable in
  isolation, and traceable to a specific formula reviewers can audit; a bug
  in scoring math is a one-file fix (`core/tools/scoring.py`), not a
  prompt-engineering problem spread across every agent.
- **Negative:** every new "the AI should compute X" idea must first be
  expressed as a deterministic function before an agent can use it — a
  deliberate constraint, not a limitation to be relaxed under time pressure
  (see `context/01_blueprint.md` §18, recommendation 2).
