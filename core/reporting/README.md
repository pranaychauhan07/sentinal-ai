# core/reporting — Report Generation & Export Pipeline

**Purpose:** The Reporting Layer (`context/01_blueprint.md` §4/§7's Report
Generator Agent, §13's exportable Executive Reports). Deterministically
aggregates every already-computed subsystem's output into a strongly-typed,
structured `GeneratedReport` — one of eight named report types (Executive
Summary, Technical Investigation, Incident Response, IOC Summary, MITRE
ATT&CK, Timeline, Threat Intelligence, Evidence) — then renders that report
to a concrete, downloadable file format. See
`docs/adr/0024-report-generator-agent.md` (generation) and
`docs/adr/0026-report-export-framework.md` (export/rendering) for the full
architecture reasoning.

## Generation (ADR-0024)

- `models.py` — `ReportType`, `ReportFormat` (PDF/HTML/Markdown/JSON/DOCX),
  `ReportSectionType`, `ReportSection`, `ReportStatistics`,
  `ReportValidationResult`, `GeneratedReport`. `ReportType` is the canonical
  enum `core/db/models/report.py` imports for column typing.
- `exceptions.py` — narrow exception hierarchy (generation-stage errors;
  export-stage errors are a sibling hierarchy, same file — see below).
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

## Export & Rendering (ADR-0026)

Every renderer/component below consumes an already-built `GeneratedReport`
only — none of them re-derive a severity, score, or mapping.

- `theme.py` — `ReportTheme`, `LIGHT_THEME`/`DARK_THEME` presets,
  `resolve_theme` — branding/color/logo/header/footer/page-numbering config
  every renderer reads.
- `asset_manager.py` — `AssetManager` (base64 data-URI embedding + a
  size/MIME guard) + `from_data_uri` (the shared decode helper).
- `charts.py` — the Plotly Visualization Engine: `severity_distribution`,
  `risk_trend`, `timeline`, `mitre_heatmap`, `ioc_categories`,
  `threat_intelligence_sources`, `finding_distribution`,
  `case_statistics` — each a pure function of a `GeneratedReport`, each
  degrading to an annotated empty figure on missing data.
- `chart_image_encoder.py` — `ChartImageEncoder` (a `Protocol`) +
  `KaleidoChartImageEncoder` (the real, Kaleido-backed static PNG
  rasterizer PDF/DOCX chart embedding needs) + `safe_encode` (never
  raises — a rendering failure degrades to "chart omitted").
- `template_engine.py` + `templates/report.html.j2` — `ReportTemplateEngine`,
  a Jinja2 wrapper restricted to a fixed template-name allowlist with
  autoescaping on — the structural template-injection defense (see
  docs/adr/0026 Decision 2).
- `html_renderer.py` — responsive, dark/light-themed, print-friendly HTML
  with embedded interactive Plotly charts and a collapsible-section
  navigation sidebar.
- `markdown_renderer.py` — headings/tables/a table of contents, charts
  embedded as base64 data-URI images.
- `pdf_renderer.py` — ReportLab Platypus flowables (never an HTML-to-PDF
  conversion — see docs/adr/0026's "Alternatives Considered"), with
  header/footer/page-numbering via the standard `_NumberedCanvas` recipe.
- `docx_renderer.py` — python-docx, real heading styles, real tables, a
  Word-computed Table-of-Contents field.
- `export_manager.py` — `ExportManager` + `ExportedReport` (bytes + media
  type + filename); the one place format dispatch, the oversized-export
  guard, and export audit/metrics events live.

## Observability

`metrics.py` / `audit.py` cover both stages in one file each (generation:
`ReportGenerationMetricsCollector`/`log_report_generation_audit_event`;
export: `ReportExportMetricsCollector`/`log_report_export_audit_event`) —
one observability surface per constitution §1.6, not two separate leaf
concerns.

## Integration

`core/tools/report_tools.py` wraps `ReportGenerationEngine` (rule 5c);
`core/agents/report_generator_agent.py` calls that tool on every evidence
upload (cross-cutting, per ADR-0024). `core/services/
report_export_service.py` (rule 4k, docs/dependency-rules.md) is the one
`core/services` module permitted to import this package directly, reading
the case's already-persisted `Report` row and rendering it on demand —
never regenerating report content, never triggering a new investigation.
`apps/api/routers/report_export.py` exposes
`GET /cases/{case_id}/reports/{formats,export,preview}`.

**Why it exists:** Reports are templated and deterministic, not LLM-freeform
text, so the same case always produces a reproducible report; exports are
rendered from that same typed model, so what an analyst previews always
matches what they download.

**Future expansion:** an `apps/web` report/export UI page (no frontend page
exists yet); asynchronous/background export generation for very large
cases; persisted export artifacts (`data/reports_out/`, `Report.file_path`
— currently always `NULL`, exports render synchronously on request); a
non-Kaleido static-chart-rendering fallback; golden-file snapshot tests
(`tests/golden/README.md` — HTML/PDF/DOCX aren't naturally byte-stable
across library versions, so correctness is asserted structurally today).
