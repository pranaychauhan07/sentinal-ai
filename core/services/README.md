# core/services — Orchestration Layer for Frontends

**Purpose:** The thin layer both `apps/web` (Streamlit) and `apps/api`
(FastAPI) call. `case_service.py` (create/list/run investigations on a case),
`evidence_service.py` (upload/classify evidence), `threat_intel_service.py`
(extract/score/classify IOCs from evidence), `finding_service.py` (map IOCs
to MITRE ATT&CK, generate/dedup/persist Findings), `report_service.py`
(generate/fetch reports).

**Responsibility:** Translates a frontend request into calls against
`core/graph`, `core/db`, and `core/reporting` — and nothing else, with three
documented exceptions: `evidence_service.py` also calls `core/parsers`
directly (evidence ingestion is deterministic, pre-investigation processing
with no agent/LLM reasoning — see `docs/adr/0011-evidence-ingestion-pipeline-shape.md`
and `docs/dependency-rules.md` rule 4a); `threat_intel_service.py` calls
`core/threat_intel` and `core/parsers` directly for the identical reason (IOC
extraction is also deterministic, pre-investigation processing — see
`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md` and
`docs/dependency-rules.md` rule 4b); and `finding_service.py` calls
`core/findings`, `core/threat_intel` (models only), and `core/knowledge`
directly for the same reason (MITRE mapping and Finding generation are also
deterministic, pre-investigation processing — see
`docs/adr/0013-finding-mitre-intelligence-engine-shape.md` and
`docs/dependency-rules.md` rule 4c). All three also call `core/memory` (the
same "check Memory for similar past cases"/case-note pattern this README
already documented as a services-level concern). This is the one place
business rules that span multiple subsystems are coordinated.

**Why it exists:** Guarantees Streamlit pages and FastAPI routers stay
interchangeable front doors to the same behavior — see `docs/dependency-rules.md`.

**Future expansion:** A CLI (`scripts/`) or a future integration would also
call these same services rather than duplicating logic.
