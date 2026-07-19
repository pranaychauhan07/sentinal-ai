# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Milestone M1 remains closed** (unchanged from last session). This session did **not** open a new milestone — it hardened/extended the M1 `Case` subsystem per an explicit, ADR-gated request: **ADR-0015, Case Management Extension** (`docs/adr/0015-case-management-extension.md`). The request initially asked for a "complete Case Management System" designed from a green-field starting point; that framing was flagged as a conflict (Case/CaseRepository/case_service/`/api/v1/cases` are production, ADR-0014-governed, and a structurally identical "build a new entity" request was already declined in a prior session for the same reason) and the work was reframed and approved as an **additive extension**, not a redesign.

### M0/M1/M2/M3/M4/M6 frameworks (unchanged from prior sessions)

- Configuration, logging, shared contracts, DB foundation, FastAPI app, governance, `core/agents`/`core/tools`/`core/graph` framework, `core/memory`/`core/knowledge` framework, `core/parsers` framework (9 parsers), `core/threat_intel` framework (20 IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine), `Case`/`Evidence`/`Finding`/`TimelineEvent`/`Report` domain models, `SocAnalystAgent`, `core/services/case_service.py`'s `investigate_new_evidence()` orchestrator, and the first `/api/v1` routes — all unchanged, see prior sessions' detail in git history / `docs/adr/0001-0014`.

### Case Management Extension (new this session, ADR-0015)

- **`CaseStatus` extended additively** — `ESCALATED`, `ON_HOLD`, `CONTAINED`, `RESOLVED`, `ARCHIVED` appended; the original `open`/`investigating`/`closed` persisted values are **unchanged** (no rename, no breaking `/api/v1` contract change). New `CasePriority` enum (low/medium/high/critical). `Case` (`core/db/models/case.py`) gained `priority`, `risk_score` (nullable float, a rollup — never written directly by a router/agent), `owner_id`/`assignee_id` (placeholder string columns matching `analyst_id`'s shape), and `labels` (freeform, unindexed, JSON-serialized `Text` column — distinct from the indexed `case_tags` table).
- **`core/db/models/case_note.py`** — `CaseNote`, a new, separate, *editable* entity distinct from `TimelineEvent.MANUAL_NOTE` (which stays exactly what it was: an immutable audit record). Every `CaseNote` create/update/delete records a paired `TimelineEvent(MANUAL_NOTE)`.
- **`core/db/models/case_tag.py`** — `CaseTag`, an indexed, unique-constrained `(case_id, tag)` join table (deliberately not a Postgres-only `ARRAY` column or an unindexed JSON blob — this project supports both PostgreSQL and SQLite). New `TimelineEventType.CASE_ASSIGNED`.
- **Two new migrations**, verified end-to-end (upgrade → downgrade → re-upgrade against a throwaway SQLite DB, schema inspected via `sqlite_master`): `031e35cdb9e7` (dialect-branching `CaseStatus` enum extension — `ALTER TYPE ... ADD VALUE` on PostgreSQL, `batch_alter_table` column rebuild on SQLite — plus the four new `Case` columns) and `e20964e060ee` (`case_notes`/`case_tags` table creation).
- **`core/services/case_lifecycle.py`** (new) — a pure, exhaustively-tested `CaseStatus` transition table (`validate_transition`/`allowed_next_statuses`). `core/services/case_service.py::update_case_status` now calls this **before** `CaseRepository.update_status`, raising the *existing* `core.exceptions.BusinessRuleError` (already documented with "closing an already-closed case" as its canonical example — no new exception class introduced) on an illegal transition. `CaseRepository.update_status` itself stays unconditional CRUD — transition validation cannot live in `core/db`, which must never import `core/services` (would be an upward, circular dependency). `ARCHIVED` is a true terminal state (no outgoing transitions).
- **`core/services/case_events.py`** (new) — `CaseEvent`/`CaseEventType` (eight types: `CASE_CREATED/_UPDATED/_ASSIGNED/_ESCALATED/_RESOLVED/_CLOSED`, `EVIDENCE_ATTACHED`, `FINDING_ATTACHED`) and `CaseEventPublisher` (injectable pub-sub, subscriber-failure-isolated, structlog-logged) — mirrors `core.findings.events.FindingEventPublisher`'s shape exactly. Distinct from `TimelineEvent`: `CaseEvent` is an in-process signal for future subscribers (a Report/Memory Agent), `TimelineEvent` is the persisted UI-facing audit narrative. Every `case_service.py` call site publishing a `CaseEvent` also records the paired `TimelineEvent` in the same function.
- **`core/services/case_metrics.py`** (new) — `CaseMetricsCollector` (status/priority counters, escalation rate, average resolution time) and `compute_case_risk_score` (the case-level risk rollup: the **maximum** `Finding.risk_score` among a case's currently-open Findings — reuses the Finding & MITRE Engine's already-persisted numbers via `FindingRepository`, never re-derives severity/risk math). Both mirror `core.findings.metrics.FindingsMetricsCollector`'s shape. Neither module — nor `case_events.py` — lives in a new `core/cases/` leaf package: `Case` has no multi-stage deterministic engine of its own (unlike Evidence/IOC/Finding), so its logic stays in `core/services`, where it already belonged. **No new `docs/dependency-rules.md` exception was needed.**
- **`core/services/case_service.py`** (extended) — new functions: `update_case_details`, `update_case_assignment`, `update_case_priority`, `update_case_labels`, `recompute_case_risk_score`, `add_case_note`/`update_case_note`/`delete_case_note`/`list_case_notes`/`get_case_note`, `add_case_tag`/`remove_case_tag`/`list_case_tags`. `create_case` gained a `priority` parameter, defaults `owner_id` to the creating analyst, and now rejects an exact `(title, analyst_id)` duplicate against a still-active case (`BusinessRuleError`, narrow/exact-match — not semantic dedup, which stays `core/memory`'s advisory-only job). `investigate_new_evidence()` now publishes `EVIDENCE_ATTACHED`/`FINDING_ATTACHED` `CaseEvent`s and recomputes `Case.risk_score` at the end of the pipeline.
- **`core/db/case_repository.py`** (extended) — `find_open_by_title_and_analyst` (the duplicate-case lookup), `update_ownership`, `update_priority`, `update_risk_score`, `update_labels_json`. `update_status` is now explicitly documented as unconditional CRUD (no behavior change to the method itself — the validation moved to `case_service`, one layer up).
- **`core/db/case_note_repository.py`**, **`core/db/case_tag_repository.py`** (new) — standard repository shape (CRUD + `find_by_case`), mirroring `CaseRepository`/`TimelineEventRepository`.
- **`apps/api/schemas.py`/`apps/api/routers/cases.py`** (extended) — `CaseResponse` gained `priority`/`risk_score`/`owner_id`/`assignee_id`. Ten new routes under `/api/v1/cases/{id}/...`: `PATCH .../details`, `PATCH .../assignment`, `PATCH .../priority`, `PATCH .../labels`, `GET`/`POST /.../tags`, `DELETE /.../tags/{tag}`, `GET`/`POST /.../notes`, `PATCH`/`DELETE /.../notes/{note_id}`. **The existing `PATCH /cases/{id}` (status) endpoint now returns `409` (`BUSINESS_RULE_VIOLATION`) on an illegal lifecycle transition** instead of unconditionally succeeding — a genuine behavior change to a shipped M1 endpoint, not a schema/contract break (verified against the pre-existing legal-transition path with a dedicated regression test).
- **Testing** — 114 new tests (776 total, up from 662): exhaustive `CaseStatus` transition-table coverage (every legal *and* illegal pair, not sampled), repository unit tests for all five new/changed repository methods plus `CaseNoteRepository`/`CaseTagRepository` (including the `case_tags` unique-constraint violation), `CaseEventPublisher`/`CaseMetricsCollector`/`compute_case_risk_score` unit tests, and integration tests covering the full `OPEN → INVESTIGATING → ESCALATED → CONTAINED → RESOLVED → CLOSED` lifecycle (asserting both `TimelineEvent`s and `CaseEvent`s fire), illegal-transition rejection without mutation, duplicate-case rejection, the note create/edit/delete audit trail, tag/priority/assignment updates, case-level risk-score recomputation after evidence upload, and the ten new API routes' success/404/409 paths (including a regression test proving the note-hijack-via-wrong-`case_id` path 404s *before* any mutation). mypy (`--strict` on `core/`), `ruff check`/`format`, `scripts/check_dependency_rules.py`, and the full pytest suite all pass.

**Explicitly NOT built, by ADR-0015's stated scope:** any Investigation/Case-correlation entity beyond `Case` itself; any specialist agent beyond `SocAnalystAgent`; any LLM reasoning; `core/security/*`; report generation; `apps/web` code; a `/api/v1/reports` route; a full CRUD/read API surface for `Case.labels` (write-only via `PATCH .../labels`, matching the `Evidence.parsed_json`/`Finding.finding_data_json` "raw serialized blob is never returned in a response schema" precedent).

---

## Repository Status

```
apps/
  api/            FastAPI app + schemas.py (MODIFIED: Case fields +
                   9 new request/response schemas) +
                   routers/{system,cases(MODIFIED: 10 new routes),
                   evidence,iocs,findings,v1}.py                    [implemented]
  web/             Streamlit frontend                                [README only]
core/
  config/         settings.py (unchanged)                            [implemented]
  logging/        (unchanged)                                        [implemented]
  exceptions.py, schemas.py, interfaces.py (unchanged — no new
                   exception classes; BusinessRuleError/NotFoundError
                   reused as-is)                                     [implemented]
  agents/         (unchanged this session)                           [implemented — 1 concrete specialist agent]
  tools/          (unchanged this session)                           [implemented — 1 concrete tool]
  memory/         (unchanged)                                        [implemented — framework only]
  knowledge/      (unchanged)                                        [implemented]
  graph/          (unchanged)                                        [implemented]
  db/             models/ (case.py MODIFIED: +CasePriority, +4
                   columns, +5 CaseStatus values; case_note.py,
                   case_tag.py NEW; timeline_event.py MODIFIED:
                   +CASE_ASSIGNED) +
                   case_repository.py (MODIFIED: +5 methods) +
                   case_note_repository.py, case_tag_repository.py
                   (NEW) +
                   migrations/versions/ (+2 NEW: enum/column
                   extension, case_notes/case_tags tables)            [implemented — 9 real domain tables + 5 reference tables]
  parsers/        (unchanged)                                        [implemented]
  threat_intel/   (unchanged)                                        [implemented]
  findings/       (unchanged)                                        [implemented]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       case_service.py (MODIFIED: +14 functions) +
                   case_lifecycle.py, case_events.py, case_metrics.py
                   (NEW) +
                   evidence_service.py, threat_intel_service.py,
                   finding_service.py (unchanged); report_service.py    [implemented]
data/             (unchanged)
scripts/          (unchanged)
tests/
  unit/           111 test modules (+5 this session: test_services_
                   case_lifecycle.py, test_services_case_events.py,
                   test_services_case_metrics.py, test_db_case_note_
                   repository.py, test_db_case_tag_repository.py;
                   +2 extended: test_db_case_repository.py)
  integration/    7 test modules (+2 extended this session:
                   test_case_service_pipeline.py, test_api_case_
                   routes.py)
  golden/         (empty — no report generation exists yet)
docs/             16 markdown docs (roadmap.md addendum) +
                   docs/adr/ (16 ADR files incl. template, +0015) +
                   docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

776 tests passing as of this session (662 prior → 776 now: 114 new). Modified this session: `core/db/models/{case,timeline_event}.py`, `core/db/case_repository.py`, `core/services/case_service.py`, `apps/api/{schemas,routers/cases}.py`, `docs/roadmap.md`, `core/db/README.md`, `core/services/README.md`, `apps/api/README.md`, `tests/unit/test_db_case_repository.py`, `tests/integration/{test_case_service_pipeline,test_api_case_routes}.py`, `CHANGELOG.md`, and this file — all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0001 through ADR-0014 per ADR-0015's explicit scoping. Ten deliberate decisions, all documented in `docs/adr/0015-case-management-extension.md`:

1. **`CaseStatus` is extended additively** — five new values, the original three unchanged/never renamed.
2. **`CaseNote` is a new, separate entity from `TimelineEvent.MANUAL_NOTE`** — audit record vs. editable content, paired on every mutation.
3. **Case-level risk score is a new aggregate** (max of open `Finding.risk_score` values), never a re-derivation of Finding-level severity math or a reuse of `RiskScoringTool`.
4. **`owner_id`/`assignee_id`** are new, nullable placeholder columns, matching `analyst_id`'s existing shape.
5. **Tags are an indexed join table** (`case_tags`), not a Postgres-only array or unindexed JSON.
6. **Labels are a single serialized JSON/Text column**, explicitly unindexed/unqueryable.
7. **`CaseEvent`/`CaseMetricsCollector` live in `core/services/`**, not a new `core/cases/` leaf package — `Case` has no multi-stage deterministic engine the way Evidence/IOC/Finding do.
8. **No new `docs/dependency-rules.md` exception required** — every new import is either a normal sibling-`core/services` call or a normal `core/db` repository call, both already-sanctioned patterns.
9. **Transition validation is a new, pure function**, called from `case_service` *before* `CaseRepository.update_status` — never inside the repository (would be an upward, circular `core/db` → `core/services` dependency).
10. **Duplicate-case protection is a narrow, exact-match heuristic** — not semantic/fuzzy dedup, which stays `core/memory`'s advisory-only job.

`docs/roadmap.md` records this as a dated addendum under M1's already-closed entry, not a new milestone checkbox. No approved architectural decision (ADR-0001 through 0014) was reversed. A pre-existing, unrelated gap was observed but not fixed: constitution §7 calls for SQLAlchemy `relationship()`/`back_populates`, but zero exist anywhere in `core/db/` today (uniform across every table) — `CaseNote`/`CaseTag` follow the established repository-query pattern for consistency rather than introducing `relationship()` unilaterally on two tables while five others lack it; reconciling this is left as its own future documentation/constitution-amendment ADR.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **A "design the complete Case Management System from scratch" framing was flagged as a conflict, not built as green-field.** `Case`/`CaseRepository`/`case_service.py`/`/api/v1/cases` are production, ADR-0014-governed subsystems; a structurally identical "new entity" request was already declined in an earlier session for the same reason (see ADR-0014's Purpose section). The work was reframed and approved as an ADR-gated *extension* (ADR-0015) — every schema change is additive, every existing endpoint's contract is preserved except one documented, deliberate behavior change (`PATCH /cases/{id}` now validates transitions).
- **`CaseStatus` was extended, never renamed** — `INVESTIGATING` stays `INVESTIGATING` (not `IN_PROGRESS`) because renaming a shipped enum value against a real persisted column and an already-versioned `/api/v1` contract is the kind of breaking change constitution §13 requires a `MAJOR` bump and its own ADR for; nothing in the actual requirement needed that.
- **`CaseRepository.update_status` cannot call `core.services.case_lifecycle.validate_transition` directly** — `core/db` is a leaf layer and `core/services` sits above it; importing upward would be circular (and `case_service.py` already imports `case_repository.py`). Validation was moved one layer up into `case_service.update_case_status`, called *before* the repository write — discovered mid-implementation, corrected before it became a real circular-import bug, and the ADR text was updated to match the corrected design.
- **`Case.labels` has no read endpoint** — matching the `Evidence.parsed_json`/`Finding.finding_data_json` precedent that raw serialized blobs are never included in a response schema. Write-only via `PATCH /cases/{id}/labels`; a structured read would need its own dedicated deserialization path, out of scope here.
- **`add_case_tag` is idempotent** (re-adding an existing `(case_id, tag)` pair returns the existing row rather than raising) — avoids a redundant duplicate-error path for a naturally idempotent action, while the underlying `case_tags` unique constraint still protects against any other write path.

---

## Public Interfaces

*(M0–M4/M6 interfaces — unchanged from prior sessions except as noted below.)*

**New/changed this session:**

`core.db.models.case.{CasePriority}` (new); `Case` gained `priority`, `risk_score`, `owner_id`, `assignee_id`, `labels`; `CaseStatus` gained `ESCALATED`, `ON_HOLD`, `CONTAINED`, `RESOLVED`, `ARCHIVED`. `core.db.models.case_note.CaseNote`, `core.db.models.case_tag.CaseTag` (new). `core.db.models.timeline_event.TimelineEventType.CASE_ASSIGNED` (new).

`core.db.case_repository.CaseRepository` gained `find_open_by_title_and_analyst`, `update_ownership`, `update_priority`, `update_risk_score`, `update_labels_json`. `core.db.case_note_repository.CaseNoteRepository`, `core.db.case_tag_repository.CaseTagRepository` (new).

`core.services.case_lifecycle.{validate_transition, allowed_next_statuses}` (new). `core.services.case_events.{CaseEvent, CaseEventType, CaseEventPublisher, CaseEventSubscriber}` (new). `core.services.case_metrics.{CaseMetricsCollector, CaseMetricsSnapshot, compute_case_risk_score}` (new).

`core.services.case_service` gained `update_case_details`, `update_case_assignment`, `update_case_priority`, `update_case_labels`, `recompute_case_risk_score`, `add_case_note`, `update_case_note`, `delete_case_note`, `list_case_notes`, `get_case_note`, `add_case_tag`, `remove_case_tag`, `list_case_tags`; `create_case` gained `priority`/`event_publisher` parameters and duplicate-case rejection; `update_case_status` gained transition validation and `event_publisher`; `investigate_new_evidence` gained `event_publisher` and now recomputes `Case.risk_score`.

`apps.api.schemas` gained `CaseDetailsUpdateRequest`, `CaseAssignmentUpdateRequest`, `CasePriorityUpdateRequest`, `CaseLabelsUpdateRequest`, `CaseTagRequest`, `CaseTagResponse`, `CaseNoteCreateRequest`, `CaseNoteUpdateRequest`, `CaseNoteResponse`; `CaseResponse`/`CaseCreateRequest` extended. New routes: `PATCH /api/v1/cases/{id}/{details,assignment,priority,labels}`, `GET`/`POST /api/v1/cases/{id}/tags`, `DELETE /api/v1/cases/{id}/tags/{tag}`, `GET`/`POST /api/v1/cases/{id}/notes`, `PATCH`/`DELETE /api/v1/cases/{id}/notes/{note_id}`.

No concrete specialist agent other than `SocAnalystAgent`, no LLM reasoning, no `/api/v1/reports` route, no `core.security.*` implementation exist as public interfaces yet.

---

## Remaining Work

1. **M2 — remaining piece.** Phishing Investigation Agent + `email_parser.py` + `core/security/prompt_guard.py`; a concrete `core/agents/mitre_mapping_agent.py` (or extended `threat_hunter_agent.py`) reasoning over `finding_service.generate_findings_for_case()`'s typed output.
2. **M3 — remaining piece.** A real Coordinator fan-out demo needs a *second* concrete specialist agent (e.g. Phishing) registered alongside `SocAnalystAgent` — the framework already supports it with zero changes.
3. **M4 — remaining piece.** Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent, Linux Security Agent, `core/agents/threat_hunter_agent.py`.
4. **M5 — Incident Response synthesis + Reporting.** Incident Response Agent, Report Generator Agent (finally gives `Report` real behavior), Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports` route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB, populate remaining knowledge data (OWASP, playbooks), Threat Timeline/MITRE heatmap/AI Analyst Chat UI (`TimelineEvent`, now with `CASE_ASSIGNED` too, already supports the Threat Timeline view).
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** a structured read endpoint for `Case.labels` (currently write-only); reconciling constitution §7's `relationship()`/`back_populates` text with the codebase's uniform "FK columns + repository queries" pattern (its own future documentation/constitution-amendment ADR).

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is not semantic; numpy not installed; `windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`; `SocAnalystAgent`'s `SocFinding[]` output is still not persisted to the `findings` table, per ADR-0014 point 4; `Report` still has no consumer.)*

- **On PostgreSQL, downgrading the `CaseStatus` enum-extension migration (`031e35cdb9e7`) is a no-op** — `ALTER TYPE ... DROP VALUE` is not supported; the five new enum values remain defined (unused) after a downgrade on that dialect. This is documented inline in the migration and treated as an accepted limitation of additive enum values, not a bug.
- **`Case.labels` has no read endpoint** (write-only via `PATCH .../labels`) — see "Remaining Work."
- **No case-level authorization/ownership check** — any request can read/write any case (`AuthenticatedUser` is still the fixed placeholder; real auth is blueprint §17 future work). `owner_id`/`assignee_id` are advisory metadata only this session, not an access-control boundary.
- **The duplicate-case guard is intentionally narrow** — exact `(title, analyst_id)` match only, not fuzzy/semantic. A near-duplicate with a slightly different title is not caught (by design, per ADR-0015 point 10 — that's `core/memory`'s advisory-only job, M6).

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session.**

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`). All prior-session work (through the M1-closing commit) is committed.

This session's Case Management Extension work added/modified (all currently uncommitted):
- New: `docs/adr/0015-case-management-extension.md`, `core/db/models/{case_note,case_tag}.py`, `core/db/{case_note_repository,case_tag_repository}.py`, `core/db/migrations/versions/{031e35cdb9e7,e20964e060ee}_*.py`, `core/services/{case_lifecycle,case_events,case_metrics}.py`, 5 new test files (`tests/unit/test_services_case_lifecycle.py`, `tests/unit/test_services_case_events.py`, `tests/unit/test_services_case_metrics.py`, `tests/unit/test_db_case_note_repository.py`, `tests/unit/test_db_case_tag_repository.py`).
- Modified: `core/db/models/{case,timeline_event}.py`, `core/db/case_repository.py`, `core/services/case_service.py`, `apps/api/{schemas,routers/cases}.py`, `docs/roadmap.md`, `core/db/README.md`, `core/services/README.md`, `apps/api/README.md`, `tests/unit/test_db_case_repository.py`, `tests/integration/{test_case_service_pipeline,test_api_case_routes}.py`, `CHANGELOG.md`, `context/current_state.md` (this file).

Full suite (776 tests), `ruff check`/`format`, `mypy core --strict`, and `scripts/check_dependency_rules.py` all pass. The two new migrations were verified end-to-end against a throwaway SQLite DB (upgrade → downgrade → re-upgrade, schema inspected directly). Commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement Milestone M2's remaining piece exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: `core/parsers/email_parser.py` (`.eml`/`.txt` phishing email parsing, producing `NormalizedEvidence` per the existing parser contract), `core/security/prompt_guard.py` (prompt-injection/jailbreak pattern detection — the first attacker-controlled-text guard, structurally required per constitution §4.11/§9/§10 before any email body reaches an LLM prompt), and `core/agents/phishing_agent.py` (a concrete `BaseAgent` subclass declaring a distinct capability, e.g. `email_triage`, so it can register alongside `SocAnalystAgent` in `core/graph/investigation_graph.py` with zero framework changes — proving the Coordinator's real fan-out for the first time, which closes M3's own demo criterion too). Wire it into `core/services/case_service.py`'s `investigate_new_evidence()` (or a parallel entry point) so a phishing email upload triggers the same `TimelineEvent`/`CaseEvent`-recording pattern this session's Case Management Extension established. Add a `POST /api/v1/cases/{id}/evidence` content-type/classification path that routes `.eml` uploads correctly (the parser factory already does extension/content sniffing — confirm it dispatches to the new parser without router changes). Preserve every existing file and architectural decision described in this document — including the extended Case lifecycle/ownership/tags/notes/events/metrics subsystem, the SOC Analyst Agent, and the Finding & MITRE Engine — only extend them.
