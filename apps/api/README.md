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

**Why it exists:** Guarantees the frontend can be swapped or a second consumer
(CLI, external integration) added without touching `core/`.

**Future expansion:** Becomes the primary interface once/if a React frontend
replaces Streamlit; also the natural home for webhook-based evidence ingestion.
