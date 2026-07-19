# core/services — Orchestration Layer for Frontends

**Purpose:** The thin layer both `apps/web` (Streamlit) and `apps/api`
(FastAPI) call. `case_service.py` (create/list/run investigations on a case),
`evidence_service.py` (upload/classify evidence), `report_service.py`
(generate/fetch reports).

**Responsibility:** Translates a frontend request into calls against
`core/graph`, `core/db`, and `core/reporting` — and nothing else, with one
documented exception: `evidence_service.py` also calls `core/parsers`
directly (evidence ingestion is deterministic, pre-investigation processing
with no agent/LLM reasoning — see `docs/adr/0011-evidence-ingestion-pipeline-shape.md`
and `docs/dependency-rules.md` rule 4a) and `core/memory` (the same
"check Memory for similar past cases"/case-note pattern this README already
documented as a services-level concern, exercised for the first time by
`evidence_service.py`'s `notify_memory` pipeline stage). This is the one
place business rules that span multiple subsystems are coordinated.

**Why it exists:** Guarantees Streamlit pages and FastAPI routers stay
interchangeable front doors to the same behavior — see `docs/dependency-rules.md`.

**Future expansion:** A CLI (`scripts/`) or a future integration would also
call these same services rather than duplicating logic.
