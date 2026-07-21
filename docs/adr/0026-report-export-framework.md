# ADR-0026: Report Export Framework

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

`core/reporting/`'s own `README.md` (written under ADR-0024) explicitly
scoped this exact work as its "Future expansion" item: *"Deliberately NOT
built yet (task instruction: 'implement only the backend models and
generation pipeline... do not build exporters yet'): `templates/` (Jinja2
report templates), `charts.py` (Plotly figure builders), `pdf_builder.py`
(Jinja2 -> ReportLab)."* This session builds exactly that — the rendering
and export layer on top of the already-shipped, unmodified
`core.reporting.models.GeneratedReport` — per an explicit task brief naming
ten required components: HTML/PDF/DOCX/Markdown Renderers, a Plotly
Visualization Engine, a Report Template Engine, a Theme System, an Asset
Manager, an Export Manager, and a Download Manager.

Blueprint §4 names the reporting stack as *"Jinja2 -> ReportLab PDF
pipeline, Plotly chart generation, executive vs. technical report
templates"* and blueprint §13 requires *"one-click PDF per module or
full-case executive summary, previewable in-app before download."* Neither
document names DOCX; the task brief does, and blueprint §5's technology
table already lists `python-docx` as a project dependency (previously used
only for *parsing* incident notes, never generation) — extending
`ReportFormat` with a fifth value is additive, not a deviation.

## Decision

Build every new component **inside the existing `core/reporting/` leaf
package**, never as a new leaf and never touching any file `report_engine.py`
already owns (`section_builders.py`, `completeness_validator.py`,
`statistics_calculator.py`, `confidence_calculator.py`, `report_engine.py`
itself) — this session extends `core/reporting/exceptions.py`, `audit.py`,
`metrics.py`, and `models.py` (additively: a fifth `ReportFormat.DOCX`
value) and adds these new modules, all consuming `GeneratedReport` as their
one input:

- `theme.py` — `ReportTheme`, `LIGHT_THEME`/`DARK_THEME` presets,
  `resolve_theme`.
- `asset_manager.py` — `AssetManager` (base64 data-URI embedding for
  HTML/Markdown, raw-bytes pass-through for PDF/DOCX, size/MIME guard) +
  `from_data_uri` (the shared decode helper both `pdf_renderer.py` and
  `docx_renderer.py` call, avoiding a duplicated decoder in each).
- `charts.py` — the task's eight named chart types
  (`severity_distribution`, `risk_trend`, `timeline`, `mitre_heatmap`,
  `ioc_categories`, `threat_intelligence_sources`, `finding_distribution`,
  `case_statistics`), each a pure function of an already-generated
  `GeneratedReport`, each degrading to an annotated empty figure rather
  than raising on missing data.
- `chart_image_encoder.py` — `ChartImageEncoder` (a `Protocol`, mirroring
  `core.conversation.llm_provider.ChatModelProvider`'s injection shape) +
  `KaleidoChartImageEncoder` (the real backend) + `safe_encode` (never
  raises; a rendering failure degrades to "chart omitted").
- `template_engine.py` + `templates/report.html.j2` — `ReportTemplateEngine`,
  a Jinja2 wrapper restricted to an explicit template-name allowlist with
  autoescaping on, the structural template-injection defense (see Decision
  2 below).
- `html_renderer.py`, `markdown_renderer.py`, `pdf_renderer.py`,
  `docx_renderer.py` — one renderer per `ReportFormat`, each independently
  constructible with injected `AssetManager`/`ChartImageEncoder` instances.
- `export_manager.py` — `ExportManager` + `ExportedReport` (bytes + media
  type + filename), the dispatcher and the one place the "oversized
  export" guard and export audit/metrics events live.
- `core/services/report_export_service.py` (new, on-demand service,
  mirroring `conversation_service.py`'s shape) — `export_report`,
  `preview_report`, `list_supported_formats`.
- `apps/api/routers/report_export.py` (new) —
  `GET /cases/{case_id}/reports/{formats,export,preview}`.

## Decision 1 — where renderers live: extending `core/reporting`, not a new leaf

`core/reporting/README.md` already named this exact file set as this
package's own future expansion, not a new package's scope. Splitting
rendering into a separate `core/report_export/` leaf would have meant
either (a) that leaf importing `core/reporting` sideways — a leaf-to-leaf
edge `docs/dependency-rules.md` rule 10 exists specifically to prevent
outside the few explicitly documented model-import exceptions — or (b)
duplicating `GeneratedReport`'s shape. Keeping renderers inside
`core/reporting` needed no new dependency-rules edge at the leaf level at
all; the only new edge is at the *services* layer (Decision 3).

## Decision 2 — template-injection defense is structural, not a runtime filter

The task explicitly names "template injection" as a threat to protect
against. `ReportTemplateEngine.render()` accepts only a `template_name`
drawn from a fixed `KNOWN_TEMPLATES` allowlist — it never accepts or
compiles a caller-supplied template *string*. Every value from case data
(a finding title, an IOC value) is passed only as a Jinja2 *context
variable*, never interpolated into template source, so even fully
attacker-controlled text cannot become executable template syntax; it can
only ever become the value autoescaping then HTML-escapes on output. This
mirrors `core/security/prompt_guard.py`'s "structurally required, not
review-dependent" shape (constitution §8) applied to a different injection
class.

## Decision 3 — a new `core/services` exception (rule 4k), not a graph node

Rendering an already-persisted `GeneratedReport` to a concrete file format
is deterministic, no-LLM-reasoning post-processing over data the
already-shipped `ReportGeneratorAgent` produced on the last evidence
upload — it is explicitly an on-demand, analyst-triggered action (blueprint
§13: "previewable in-app before download"), never part of the automatic
per-upload investigation pipeline. This is the same shape ADR-0025 chose
for the AI Analyst Chat: a new `core/services/report_export_service.py`
gets a narrowly-scoped, documented dependency-rules.md exception (**rule
4k**, worded identically to the established 4a-4j family) to import
`core/reporting` directly, rather than inventing a `core/graph` node that
would regenerate on every upload for a capability that only ever runs when
an analyst clicks "export."

## Decision 4 — no persisted export artifacts; render-on-request only

Exports are rendered synchronously, in-memory, per request — never written
to `data/reports_out/` or the `Report.file_path` column (which stays
`NULL`, unchanged from ADR-0024). Blueprint §6's folder plan names
`data/reports_out/` as a future artifact location, but nothing in this
task's scope requires a persisted file: `GeneratedReport` is already
durable (one row per case, `report_data_json`), so re-rendering an export
on the next request costs one deterministic render, not a re-run of the
investigation pipeline. Adding disk persistence later is a strict addition
behind the same `ExportedReport` shape, not a redesign.

## Decision 5 — Kaleido as a new, justified dependency for static chart export

`plotly` (already a dependency) can embed *interactive* charts in HTML with
no extra library (`plotly.offline.get_plotlyjs()`, embedded inline once per
document — genuinely offline-viewable, no CDN). PDF and DOCX are static
formats; embedding a chart there requires a rasterized PNG, which requires
`kaleido` (Plotly's own, official static-image exporter, headless-Chrome-
backed). This is a new dependency (`requirements.txt`, justified inline)
verified to install and function in this environment. To keep the real
~1-2s/chart, real-subprocess cost out of the fast test tiers, chart
rasterization is isolated behind the `ChartImageEncoder` protocol
(`chart_image_encoder.py`) — every renderer/export-manager unit and
integration test injects a fake, millisecond-cost encoder; only a manual
smoke test (recorded below) exercises the real Kaleido/Chrome path.

**Manual smoke test performed this session** (not part of the automated
suite, recorded here for auditability): built a `GeneratedReport` with six
populated sections and called `ExportManager().export(report, fmt,
include_charts=True)` for every `ReportFormat` using the real
`KaleidoChartImageEncoder` — HTML (4.9 MB, embedded Plotly JS), Markdown
(1.5 KB + inline data-URI chart images), JSON (3.5 KB), PDF (81 KB, ~16.7s
for 8 real chart renders), DOCX (36 KB). All five produced valid,
openable documents.

## Decision 6 — graceful degradation for every failure mode named in scope

- **Malformed report data:** every value pulled from `ReportSection.content`
  (a `dict[str, object]` with no static shape guarantee) is read
  defensively (`_safe_int`, `isinstance` narrowing) — a chart or renderer
  never raises on an unexpected type, it degrades to an empty/placeholder
  view (constitution §1.7).
- **Oversized exports:** `ExportManager` measures the report's serialized
  size against `DEFAULT_MAX_REPORT_EXPORT_BYTES` (25 MiB) before rendering
  and raises a typed `OversizedReportExportError`, mirroring
  `report_engine.py`'s own generation-side guard.
- **Unsafe embedded content:** Decision 2 (HTML/template injection) plus
  Markdown's own `_escape_markdown` (a case value containing `|`/`*`/`#`
  can never corrupt Markdown table/heading structure).
- **Chart rendering unavailable** (no Chrome/Kaleido in a given
  deployment): `safe_encode` catches `ChartRenderingError` and every
  PDF/DOCX/Markdown renderer inserts a documented "chart rendering
  unavailable" note instead of aborting the whole export — proven by a
  dedicated test in each renderer's unit-test module with a
  `_FailingChartImageEncoder`.

## Alternatives Considered

- **A literal Jinja2-HTML-to-PDF pipeline** (rendering `report.html.j2` and
  converting it to PDF with a library like WeasyPrint/xhtml2pdf). Rejected:
  no such dependency exists in this project and adding one duplicates
  ReportLab's job; blueprint §4's "Jinja2 -> ReportLab" is satisfied as
  "Jinja2 for HTML/Markdown, ReportLab (Platypus flowables driven directly
  from `GeneratedReport`) for PDF," both against the same source of truth,
  documented explicitly in `pdf_renderer.py`'s module docstring so a future
  reader doesn't mistake this for an oversight.
- **A new `core/report_export/` leaf package.** Rejected per Decision 1 —
  `core/reporting/README.md` already scoped this as an extension of the
  existing package, and a sideways leaf-to-leaf import would have violated
  `docs/dependency-rules.md` rule 10 without a genuine architectural need.
- **Persisting rendered exports to disk / `Report.file_path`.** Rejected
  per Decision 4 — not required by this task's scope, and render-on-request
  is simpler and avoids a stale-cache invalidation problem (what happens
  when the underlying `GeneratedReport` changes but a stale PDF sits on
  disk) that this design structurally cannot have.
- **A registry-based, mutable `Theme` plugin system.** Rejected — a
  documented, immutable `BUILT_IN_THEMES` mapping plus "pass any
  `ReportTheme` instance directly" already satisfies "future template
  plugins" (the task's own phrase) without introducing mutable global
  state (constitution §2).

## Consequences

**Easier:** An analyst (or, today, an API caller — no `apps/web` chat/report
UI page exists yet, see below) can generate a professional, branded,
themed report in any of five formats from a case's already-computed
findings, with zero risk of fabricated content (every renderer only ever
reads `GeneratedReport`, never invents a fact) and zero risk of template
injection (Decision 2, structural). The `ChartImageEncoder`/`ChatModelProvider`-
style injection seam means a future non-Kaleido rasterizer (or a
disk-caching layer) is a constructor-parameter swap, not a rewrite.

**Harder / foreclosed:** PDF/DOCX chart embedding now has a real, non-trivial
runtime dependency (a working Kaleido/Chrome install) — a deployment
without it still produces a complete, valid PDF/DOCX (Decision 6), just
without chart images, a disclosed degradation rather than a hard failure.
Rendering cost for PDF/DOCX with all eight charts is measurably higher
(~15-20s) than the HTML/Markdown/JSON paths (sub-second) — acceptable for
an on-demand, analyst-triggered action, not acceptable if this framework
were ever wired into the automatic per-upload pipeline (a reason, beyond
Decision 3's architectural one, this stays on-demand).

**Never touched:** `core/reporting/{models,inputs,section_registry,
section_builders,completeness_validator,statistics_calculator,
confidence_calculator,report_engine}.py` (except `models.py`'s additive
`ReportFormat.DOCX` value), `core/tools/report_tools.py`,
`core/agents/report_generator_agent.py`, `core/graph/*`, and every prior
agent/framework — this session is purely additive over an unmodified
generation pipeline.

## Explicitly NOT built this session

The `apps/web` report/export UI page (no Streamlit page exists for this
yet — this session is API/backend only, per this task's own scope, which
never named a frontend deliverable); asynchronous/background export
generation (the task named it as a "Future" item explicitly, not required
now — every export renders synchronously within one HTTP request);
persisted export artifacts / `data/reports_out/` (Decision 4); a
non-Kaleido static-chart-rendering fallback (the graceful-degradation path
in Decision 6 covers the "Kaleido unavailable" case without needing a
second rasterizer implementation); golden-file snapshot tests for rendered
output (`tests/golden/` stays empty — HTML/PDF/DOCX byte content is not
naturally snapshot-stable across ReportLab/python-docx library versions or
embedded timestamps, so correctness here is asserted structurally — valid
document, expected headings/tables/escaping present — not byte-for-byte,
consistent with this repository's existing golden-test scope boundary).
