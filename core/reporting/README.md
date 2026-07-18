# core/reporting — PDF and Chart Generation

**Purpose:** The Reporting Layer (`context/01_blueprint.md` §4). Converts a
finalized `CaseState` into module-level and case-level executive PDF reports.

**Responsibility:** `templates/` holds Jinja2 report templates (one per module
plus an executive summary template). `charts.py` builds the Plotly figures
(severity pie, MITRE tactic bar, timeline) shared between the in-app dashboard
and the PDF export. `pdf_builder.py` renders Jinja2 → ReportLab.

**Why it exists:** Reports are templated and deterministic, not LLM-freeform
text, so the same case always produces a reproducible report (golden-file
tested — see `tests/golden/README.md`).

**Future expansion:** Additional report formats (DOCX, HTML) would be added as
new builders consuming the same Jinja2 templates and Plotly figures.
