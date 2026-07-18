# ADR-0001: Layered, Case-Centric Architecture

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

The capstone spec (Project 9) lists nine largely independent modules
(phishing, log analysis, vulnerability scanning, OWASP review, etc.). Built
literally as nine separate tools, the result is nine disconnected demos with
duplicated scoring/reporting logic and no way to correlate evidence from the
same real-world incident. We needed to decide the organizing principle for
the whole system before writing any agent code.

## Decision

Build around a `Case` as the central domain object (`Case → Evidence →
Finding → TimelineEvent`), with a layered architecture (frontend → API →
workflow → agents → tools → parsers → knowledge → memory → security → db →
reporting) where every module's output is a `Finding` attached to a `Case`,
not a standalone report. See `context/01_blueprint.md` §1 and §4.

## Alternatives Considered

- **Nine independent Streamlit apps/scripts, one per module** — matches the
  PDF's module list most literally, but forecloses cross-evidence
  correlation, duplicates risk-scoring and reporting code nine times, and
  reads as a capstone checklist rather than a platform.
- **A single monolithic script with `if evidence_type == ...` branching** —
  no persistence, no orchestration, no path to multi-agent behavior; would
  need a full rewrite to add memory or cross-case learning.

## Consequences

- **Positive:** one scoring engine, one report pipeline, one persistence
  layer; cross-evidence correlation (shared IOCs across a phishing email and
  a firewall log) becomes possible instead of architecturally excluded;
  every future module is additive (a new agent + parser), not a new app.
- **Negative:** more upfront scaffolding before the first module is "done"
  (a real DB schema, a real orchestrator) — accepted deliberately per
  blueprint §18 ("build the data model in M0, before any agent exists").
