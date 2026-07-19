# ADR-0015: Case Management Extension — Lifecycle, Ownership, Risk, Tags/Notes, Events

**Status:** Accepted
**Date:** 2026-07-20

## Purpose

Milestone M1 (ADR-0014) shipped the minimum `Case` subsystem needed to close
its own demo criterion: `Case`/`TimelineEvent`/`Report` models, `CaseRepository`,
`case_service.py`'s orchestration, and the first `/api/v1/cases` routes. It
deliberately left out everything blueprint §13's Investigation Workspace and
§7's per-case triage workflow imply but M1 didn't need yet: ownership vs.
assignment, priority, a case-level risk score, tags/labels, editable analyst
notes, an escalation-capable lifecycle, and validated state transitions.

A request framed this gap as "design the complete Case Management System"
from a green-field starting point. It isn't green field: `Case` is
production, ADR-0014-governed, and a structurally identical prior request (a
new `Investigation` entity duplicating `Case`'s and `TimelineEvent`'s already-
assigned responsibilities) was declined for exactly this reason. This ADR
scopes the actual gap as an **extension** of the existing subsystem —
`Case`, `CaseRepository`, `case_service.py`, and the existing
`/api/v1/cases` routes are not redesigned; every change below is additive
(constitution §7 "Future scalability", §14.10).

## Decisions

1. **`CaseStatus` is extended additively, not renamed.** The persisted values
   `open`/`investigating`/`closed` are unchanged — no existing row or `/v1`
   API contract breaks. Five new values are appended: `escalated`,
   `on_hold`, `contained`, `resolved`, `archived`. A UI wanting to display
   "In Progress" instead of "Investigating" does that as a presentation-layer
   label mapping (`apps/web`/`apps/api` schema docs), never a persisted
   rename — renaming a shipped enum value against a real column and a
   already-versioned `/api/v1` contract is the kind of breaking change
   constitution §13 requires a `MAJOR` bump and its own ADR for, which
   nothing about this task's actual requirement needs.

2. **`CaseNote` is a new, separate entity from `TimelineEvent.MANUAL_NOTE`.**
   `TimelineEvent` stays exactly what it already is: an immutable,
   append-only audit trail. A `CaseNote` is mutable analyst commentary — it
   has its own `id`/`created_at`/`updated_at`/`author_id` and can be created,
   updated, or deleted independently of the timeline. Every `CaseNote`
   mutation (create/update/delete) records a corresponding
   `TimelineEvent(event_type=MANUAL_NOTE)` — the audit trail always reflects
   that *a* note-related action happened and by whom, even though the note's
   live content lives in `CaseNote`, not by replaying timeline narratives.
   This avoids constitution §14.9's "never duplicate functionality" (the two
   entities have genuinely different responsibilities — audit record vs.
   live content) while keeping exactly one audit mechanism.

3. **Case-level risk score is a new aggregate, not a reuse of
   `RiskScoringTool` or a re-derivation of Finding-level severity math.**
   `core/tools/scoring.py::RiskScoringTool` scores one evidence artifact,
   pre-Finding (ADR-0014 point 5). Case-level risk is a rollup of the
   `Finding.risk_score` values **already persisted** by the Finding & MITRE
   Engine (ADR-0013) for that case — `core/services/case_metrics.py`
   computes it as the maximum `risk_score` among the case's non-`CLOSED`
   Findings (an analyst triages by worst-open-finding, matching how
   `core/services/case_service.py::_extract_soc_risk` already picks the
   `max` across `SocFinding`s for the identical reason). No new scoring
   math is invented; this is aggregation of an existing, already-tested
   number, satisfying constitution Principle 9 ("one source of truth" per
   score type) without adding a third one.

4. **`owner_id`/`assignee_id` are new, nullable placeholder string columns**,
   matching `Case.analyst_id`'s existing placeholder shape exactly (no real
   `User` table exists yet — blueprint §17). `owner_id` is the case's
   accountable analyst (defaults to the creating analyst); `assignee_id` is
   who is actively working it now — distinct concepts a single-analyst mode
   doesn't strictly need but blueprint §17 already anticipates.

5. **Tags are a new, indexed join table (`case_tags`)**, not a
   dialect-specific array column or an unindexed JSON blob — this project
   supports both PostgreSQL and SQLite (blueprint §4), and `ARRAY` is
   Postgres-only. Tags are filterable, structured, flat strings.

6. **Labels are a single serialized JSON/Text column on `Case`** (`labels`),
   for freeform key→value metadata that is *not* meant to be queried or
   indexed — explicitly documented as such, distinct from tags' query-time
   role, matching the `Evidence.parsed_json`/`Finding.finding_data_json`
   "ORM row is the persistence representation, structured access happens one
   layer up" precedent.

7. **`CaseEvent`/`CaseMetricsCollector` live in `core/services/`, sibling to
   `case_service.py` — not a new `core/cases/` leaf package.** Unlike
   Evidence/IOC/Finding, `Case` has no multi-stage deterministic engine of
   its own (no parser/extractor/mapper equivalent); its logic is
   orchestration, already `core/services`' documented job. `core/findings/
   events.py` and `core/threat_intel/events.py` live in dedicated leaf
   packages because those wrap real multi-stage engines below
   `core/services`; inventing an equivalent `core/cases` leaf package here
   would be architecture-for-its-own-sake (constitution §1.10). The new
   modules mirror `core.findings.events.FindingEventPublisher`'s and
   `core.findings.metrics.FindingsMetricsCollector`'s shape exactly
   (injectable pub-sub, no module-level mutable state, structlog-logged).

8. **No new `docs/dependency-rules.md` exception is required.**
   `case_metrics.py`'s read of persisted `Finding.risk_score` goes through
   `core/db/finding_repository.py::FindingRepository`, already a normal
   `core/db` repository call `core/services` modules make everywhere else
   (rule 7) — it does not reach into `core/findings`' internals directly.
   `case_events.py`/`case_metrics.py` themselves have zero dependencies
   beyond `pydantic`/`core.logging`, identical to `core.findings.events`'s
   shape. Rule 4d (ADR-0014) is unaffected — this extension adds no new
   import edge to `case_service.py` beyond what rule 4d already grants plus
   ordinary sibling-service/repository calls.

9. **Transition validation is a new, pure, exhaustively-tested function**
   (`core/services/case_lifecycle.py::validate_transition`), not inline `if`
   statements scattered across the repository/service/router. It is called
   from `core/services/case_service.py::update_case_status` **before**
   `CaseRepository.update_status` is invoked — not from inside the
   repository itself, since `core/db` is a leaf layer and importing
   `core/services` from it would be an upward, circular dependency
   (`docs/dependency-rules.md`'s layer stack: `core/services` sits above
   `core/db`, not below it). `CaseRepository.update_status` remains
   unconditional CRUD, matching constitution §1.4's "a repository is CRUD,
   a service coordinates" split. An illegal transition raises the existing
   `core.exceptions.BusinessRuleError` (already documented with "e.g.
   attempting to close an already-closed case" as its canonical example) —
   no new exception class is introduced.

10. **Duplicate-case protection is a narrow, exact-match heuristic, not
    semantic/fuzzy dedup.** `case_service.create_case` rejects (via the
    same `BusinessRuleError`) an exact `(title, analyst_id)` match against a
    case currently `OPEN`/`INVESTIGATING`/`ESCALATED`/`ON_HOLD`/`CONTAINED`
    (i.e. not yet `RESOLVED`/`CLOSED`/`ARCHIVED`). This is intentionally
    cheap and exact — semantic "have we seen this before" similarity is
    `core/memory`'s Chroma-backed advisory retrieval (blueprint §7 Memory
    Agent, M6), already scoped elsewhere and never a hard block. Building
    more here would be designing for a requirement nothing in this task or
    the blueprint actually states (constitution Principle 3).

## Consequences

- `docs/roadmap.md` is not updated with a new milestone checkbox — this is a
  hardening/extension pass on M1's already-closed scope, recorded as a dated
  addendum under M1's existing entry, not a new roadmap item.
- The existing `PATCH /api/v1/cases/{id}` (status) endpoint gains new
  behavior: an illegal transition now returns `409` via the standard error
  envelope instead of unconditionally succeeding. This is a genuine behavior
  change to a shipped endpoint, not a schema/contract break (the request/
  response shapes are unchanged) — called out explicitly here and in
  `CHANGELOG.md` per constitution §13's spirit, without requiring a `/v2`
  cutover.
- `Report` generation, LLM reasoning, investigation logic, and every
  specialist agent beyond `SocAnalystAgent` remain explicitly out of scope —
  unchanged from ADR-0011/0012/0013/0014's identical scope cuts.
- A pre-existing, unrelated gap is observed but not fixed here: constitution
  §7 calls for SQLAlchemy `relationship()`/`back_populates` declarations, but
  none exist anywhere in `core/db/` today (every table is FK-columns +
  repository queries, uniformly, across `Evidence`/`IOC`/`Finding`/
  `TimelineEvent`/`Report`). The new `CaseNote`/`CaseTag` tables follow the
  same established repository-query pattern for consistency with every
  sibling table, rather than introducing `relationship()` unilaterally on
  two tables while five others lack it. Reconciling the constitution's text
  with the codebase's actual, uniform pattern is left as its own future
  documentation/constitution-amendment ADR, out of scope here.
