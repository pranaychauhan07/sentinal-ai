# core/reporting — Report Generation Pipeline

**Purpose:** The Reporting Layer (`context/01_blueprint.md` §4/§7's Report
Generator Agent). Deterministically aggregates every already-computed
subsystem's output into a strongly-typed, structured `GeneratedReport` — one
of eight named report types (Executive Summary, Technical Investigation,
Incident Response, IOC Summary, MITRE ATT&CK, Timeline, Threat Intelligence,
Evidence). See `docs/adr/0024-report-generator-agent.md` for the full
architecture reasoning.

**Responsibility (built, this milestone):**

- `models.py` — `ReportType`, `ReportFormat`, `ReportSectionType`,
  `ReportSection`, `ReportStatistics`, `ReportValidationResult`,
  `GeneratedReport`. `ReportType` is the canonical enum `core/db/models/
  report.py` imports for column typing.
- `exceptions.py` — narrow exception hierarchy.
- `inputs.py` — `ReportGenerationContext`, the one normalized shape every
  upstream subsystem's already-computed signal is reduced to.
- `section_registry.py` — the static table of which sections each report
  type includes, and each type's default title.
- `section_builders.py` — one pure function per `ReportSectionType`,
  aggregating already-computed data only — never LLM reasoning, never a
  re-derived severity/score/mapping (constitution §1.9).
- `completeness_validator.py` — the "Validate Completeness" pipeline stage.
- `statistics_calculator.py` — the "Calculate Statistics" pipeline stage.
- `confidence_calculator.py` — the report-level confidence rollup.
- `report_engine.py` — `ReportGenerationEngine`, the pipeline orchestrator:
  generate sections -> assemble -> validate -> calculate statistics -> build
  `GeneratedReport`.
- `metrics.py` / `audit.py` — observability, mirroring every other leaf
  package's established shape.

**Why it exists:** Reports are templated and deterministic, not LLM-freeform
text, so the same case always produces a reproducible report.

**Deliberately NOT built yet (task instruction: "implement only the backend
models and generation pipeline... do not build exporters yet"):**
`templates/` (Jinja2 report templates), `charts.py` (Plotly figure
builders), `pdf_builder.py` (Jinja2 → ReportLab). `GeneratedReport` is
already structured to support all four `ReportFormat` values (PDF, HTML,
Markdown, JSON) equally — a future session adds the concrete exporters
against this same typed model, not a redesign of it.

**Future expansion:** `templates/`, `charts.py`, `pdf_builder.py` (per
above); an on-demand `/api/v1/cases/{case_id}/reports` route to request any
of the eight report types directly (today only the Technical Investigation
Report auto-regenerates on every evidence upload, via
`ReportGeneratorAgent`); golden-file snapshot tests once a concrete renderer
exists (`tests/golden/README.md`).
