# components — Reusable Streamlit Widgets

Presentation-only helpers shared across pages: case summary cards, severity
color-coded badges, Plotly chart wrappers, the Investigation Trail (ReAct
Thought log) panel. No business logic — pure rendering functions that accept
already-computed data.

**Built:** `badges.py` (severity/status badges, confidence labeling),
`cards.py` (case summary cards), `charts.py` (severity donut, MITRE bar,
timeline scatter — plain Plotly figures built from already-fetched
`core/services` data, independent of `core/reporting/charts.py`), and
`case_picker.py` (the shared case-selection widget every case-scoped page
uses, backed by `st.session_state["case_id"]`). The Investigation Trail
(ReAct Thought log) panel remains unbuilt — no `core/services` function
currently surfaces per-agent `thought` text to a UI consumer; named as
future work.
