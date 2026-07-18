# ADR-0007: Templated Report Engine (Jinja2 → ReportLab, Not LLM-Freeform)

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

Executive PDF reports are a required deliverable for every module. We needed
to decide whether report *content* is generated freeform by an LLM per
request, or assembled deterministically from structured findings, before
building `core/reporting/`.

## Decision

Reports are built from Jinja2 templates (`core/reporting/templates/`, one per
module plus an executive summary) rendered against typed Pydantic finding
models, then converted to PDF via ReportLab. Plotly builds the charts
(`core/reporting/charts.py`), shared between the in-app dashboard and the PDF
export. The LLM contributes narrative *text fields* (e.g. an "Executive
Summary" paragraph an agent already produced), but never controls report
*structure* or *layout*. See `context/01_blueprint.md` §4–§5.

## Alternatives Considered

- **Ask an LLM to generate the full report (Markdown/HTML) per request** —
  faster to prototype, but produces a different report structure every run
  even for identical findings, which is untestable (no stable golden-file
  comparison) and unacceptable for a document meant to be handed to
  management/auditors expecting consistent formatting.
- **Hand-written string concatenation instead of a templating engine** —
  works initially but becomes unmaintainable as report sections grow;
  rejected in favor of Jinja2's separation of layout from data.

## Consequences

- **Positive:** the same case always produces a reproducible report,
  enabling golden-file snapshot tests (`tests/golden/`) that catch template
  regressions; report layout can be redesigned without touching agent code,
  since agents only ever produce data, not markup.
- **Negative:** adding a new report section requires a template change in
  addition to a data-model change — an intentional two-step process that
  keeps data and presentation decoupled rather than a convenience cost worth
  removing.
