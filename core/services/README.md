# core/services — Orchestration Layer for Frontends

**Purpose:** The thin layer both `apps/web` (Streamlit) and `apps/api`
(FastAPI) call. `case_service.py` (create/list/run investigations on a case),
`evidence_service.py` (upload/classify evidence), `report_service.py`
(generate/fetch reports).

**Responsibility:** Translates a frontend request into calls against
`core/graph`, `core/db`, and `core/reporting` — and nothing else. This is the
one place business rules that span multiple subsystems (e.g. "creating a case
also checks Memory for similar past cases") are coordinated.

**Why it exists:** Guarantees Streamlit pages and FastAPI routers stay
interchangeable front doors to the same behavior — see `docs/dependency-rules.md`.

**Future expansion:** A CLI (`scripts/`) or a future integration would also
call these same services rather than duplicating logic.
