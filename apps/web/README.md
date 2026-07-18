# apps/web — Streamlit Frontend

**Purpose:** The analyst-facing UI (Phase 1–4 per the blueprint). Multi-page Streamlit
application: dashboard, case management, investigation workspace, chat, reports, settings.

**Responsibility:** Render state and collect user input ONLY. This layer must never
contain business logic, scoring math, or agent orchestration — it calls
`core/services/*` and displays the result. This is a hard architectural rule (see
`docs/dependency-rules.md`) that keeps a future React/FastAPI split a swap, not a rewrite.

**Typical files:** `Home.py` (entry point), `pages/1_Case_Dashboard.py`,
`pages/2_New_Investigation.py`, etc., `components/` (reusable widgets: case cards,
severity badges, chart wrappers).

**Why it exists:** The PDF's Project 9 requires a Streamlit dashboard; this is that
dashboard, structured so it stays thin.

**Future expansion:** Swapped for or supplemented by a React frontend once Streamlit's
UI ceiling is reached (`apps/api` already exists for exactly this transition).
