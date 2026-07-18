# ADR-0003: LangGraph for Multi-Agent Orchestration

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

The system needs to run a variable set of specialist agents per case (a
case with only a phishing email skips the Vulnerability Agent entirely),
needs explicit ReAct-style reasoning steps, and needs to survive a mid-
investigation failure (an LLM API timeout) without losing prior progress.
We needed to pick the orchestration framework before writing any agent code,
since it shapes every agent's interface.

## Decision

Use LangGraph's `StateGraph` as the Workflow Layer (`core/graph/`), with a
single typed `CaseInvestigationState` object every node reads/writes, and
conditional edges (`core/graph/routing.py`) selecting which specialist agents
run for a given case. See `context/01_blueprint.md` §4, §11.

## Alternatives Considered

- **Plain LangChain chains (`SequentialChain`/`LLMChain`)** — adequate for a
  fixed linear pipeline, but cannot cleanly express conditional branching
  (skip an agent based on evidence type) or checkpointing/resume; would
  require hand-rolled control flow around the chains anyway, defeating the
  point of using a framework.
- **Hand-rolled orchestrator (a Python class with `if`/`elif` dispatch)** —
  fully flexible but reinvents state management, retries, and checkpointing
  from scratch, with no ecosystem tooling (e.g. LangGraph Studio for
  visualizing/debugging the graph) or long-term community support.
- **CrewAI or AutoGen** — both are viable multi-agent frameworks, but
  LangGraph's explicit state-machine model (nodes + typed shared state) maps
  more directly onto "a Case investigation is a graph of steps with branches"
  than CrewAI's role-based delegation model or AutoGen's conversational
  multi-agent chat model, which fit less naturally with our requirement for
  deterministic, auditable control flow.

## Consequences

- **Positive:** control flow is explicit and inspectable (a real graph, not
  buried imperative logic); checkpointing enables resuming a failed
  investigation; the framework is the same one the capstone spec explicitly
  names for Project 9.
- **Negative:** LangGraph is a comparatively young framework — API surface
  can shift between versions; pinned in `requirements.txt` and upgraded
  deliberately, never silently via a floating version range.
