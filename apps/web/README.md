# apps/web — Streamlit Frontend

**Purpose:** The analyst-facing UI (Phase 1–4 per the blueprint). Multi-page Streamlit
application: dashboard, case management, investigation workspace, chat, reports, settings.

**Responsibility:** Render state and collect user input ONLY. This layer must never
contain business logic, scoring math, or agent orchestration — it calls
`core/services/*` and displays the result. This is a hard architectural rule (see
`docs/dependency-rules.md`) that keeps a future React/FastAPI split a swap, not a rewrite.

**Built this session** — the first, and previously entirely missing, `apps/web` code:
- `runtime.py` — the sync/async bridge Streamlit needs (it has no native `async def`
  page support; `core/services` is all `async def`). A cached `Database` singleton
  (`st.cache_resource`, mirroring `apps/api/main.py`'s lifespan-scoped instance) +
  `run_async()`, which opens a request-scoped session (commit-on-success/rollback-on-
  failure, identical contract to `apps/api/dependencies.py`'s `get_db_session`), runs one
  `core/services` call to completion inside a fresh `asyncio.run()`, and returns the
  result. Every page calls `core/services` through this, never constructs its own
  session/event loop.
- `theme.py` — dark-theme CSS injection + `st.set_page_config`, palette inspired by the
  Claude-Design mockup handed off for this build (see the mockup's own
  `AI Cyber Defense Copilot-handoff/` bundle) — recreated as a Streamlit theme, not a
  pixel-for-pixel port (that mockup's custom flexbox shell/blur/gradient chrome isn't
  reproducible in Streamlit's component model; React was considered and Streamlit chosen
  for this phase per the blueprint's own phasing).
- `components/{badges,cards,charts,case_picker}.py` — severity/status badges, case
  cards, Plotly wrappers (severity donut, MITRE bar, timeline scatter — deliberately
  independent of `core/reporting/charts.py`, which builds from an already-*generated*
  report, not a live cross-case/dashboard query), and the shared case-selection widget
  every case-scoped page uses (Streamlit has no native cross-page routing state, so the
  chosen case id lives in `st.session_state["case_id"]`).
- `Home.py` + `pages/1_Case_Dashboard.py` through `pages/8_Settings.py` — every
  blueprint §6/§13-named page, each calling exactly one `core/services` function per
  user action (Case Dashboard/New Investigation → `case_service`; Evidence Explorer →
  `evidence_service`/`finding_service`/`threat_intel_service`; Threat Timeline →
  `case_service.list_timeline_for_case`; MITRE Map → the new
  `finding_service.list_mitre_mappings_for_case`; AI Analyst Chat →
  `conversation_service` (ADR-0025/0027/0028/0029's full pipeline, now with a UI);
  Executive Reports → `report_export_service` (ADR-0026); Settings → read-only
  `core.config.Settings` display, since no settings-mutation API exists).

**Why it exists:** The PDF's Project 9 requires a Streamlit dashboard; this is that
dashboard, structured so it stays thin.

**Future expansion:** Swapped for or supplemented by a React frontend once Streamlit's
UI ceiling is reached (`apps/api` already exists for exactly this transition) — the
Claude-Design mockup this session's visual choices were inspired by remains available as
a higher-fidelity target for that future React build.
