# apps/api — FastAPI Service Boundary

**Purpose:** Typed HTTP API exposing the same `core/services/*` functions the
Streamlit app calls in-process. Built from day one (Phase 1+) even though nothing
calls it yet over the network — see `docs/adr/0002-fastapi-service-boundary.md`.

**Responsibility:** Request/response validation (Pydantic), auth boundary (future),
routing to services. No business logic lives here either — routers are thin.

**Typical files:** `main.py` (app factory), `routers/cases.py`,
`routers/evidence.py`, `routers/reports.py`.

**Why it exists:** Guarantees the frontend can be swapped or a second consumer
(CLI, external integration) added without touching `core/`.

**Future expansion:** Becomes the primary interface once/if a React frontend
replaces Streamlit; also the natural home for webhook-based evidence ingestion.
