# apps/api — FastAPI Service Boundary

**Purpose:** Typed HTTP API exposing the same `core/services/*` functions the
Streamlit app calls in-process. Built from day one (Phase 1+) even though nothing
calls it yet over the network — see `docs/adr/0002-fastapi-service-boundary.md`.

**Responsibility:** Request/response validation (Pydantic), auth boundary (future),
routing to services. No business logic lives here either — routers are thin.

**Implemented (Milestone M1, `docs/adr/0014-case-model-and-first-api-routes-shape.md`):**
`schemas.py` (request/response Pydantic models), `routers/cases.py`
(`POST`/`GET`/`PATCH /cases`, `GET /cases/{id}/timeline`),
`routers/evidence.py` (`POST /cases/{id}/evidence` — synchronously runs the
full ingest → extract → generate → analyze pipeline via
`core.services.case_service.investigate_new_evidence`), `routers/iocs.py`
and `routers/findings.py` (read-only lists). No `routers/reports.py` yet —
report generation is Milestone M5.

**ADR-0015 (Case Management Extension)** added to `routers/cases.py`:
`PATCH /cases/{id}/details|assignment|priority|labels`, `GET`/`POST
/cases/{id}/tags`, `DELETE /cases/{id}/tags/{tag}`, `GET`/`POST
/cases/{id}/notes`, `PATCH`/`DELETE /cases/{id}/notes/{note_id}`. The
existing `PATCH /cases/{id}` (status) endpoint now returns `409` via the
standard error envelope on an illegal lifecycle transition instead of
unconditionally succeeding — a genuine behavior change to a shipped
endpoint, not a schema/contract break (documented in the ADR and
`CHANGELOG.md`).

**Why it exists:** Guarantees the frontend can be swapped or a second consumer
(CLI, external integration) added without touching `core/`.

**Future expansion:** Becomes the primary interface once/if a React frontend
replaces Streamlit; also the natural home for webhook-based evidence ingestion.
