"""Narrow exception hierarchy for `core/reporting` — constitution §5 ("every
tool module defines its own narrow exception classes"), mirroring
`core/incident_response/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class ReportGenerationError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "REPORT_GENERATION_ERROR"


class UnknownReportTypeError(ReportGenerationError):
    """A `ReportType` was requested that `section_registry.py` has no
    section mapping for — should be unreachable for any real `ReportType`
    member (the registry is exhaustive over the enum, enforced by a unit
    test), but guarded explicitly rather than raising a bare `KeyError`."""

    code = "UNKNOWN_REPORT_TYPE"


class OversizedReportInputError(ReportGenerationError):
    """The combined size of the context handed to
    `report_engine.ReportGenerationEngine` (findings + evidence + vulnerability/
    linux/owasp records) exceeds the configured maximum — the resource-
    exhaustion guard for a pathologically large case, mirroring
    `core.incident_response.exceptions.OversizedFindingSetError`'s identical
    reasoning."""

    code = "OVERSIZED_REPORT_INPUT"


class ReportExportError(ReportGenerationError):
    """Base class for every exception the export/rendering layer
    (`export_manager.py`, `*_renderer.py`, `charts.py`, `template_engine.py`,
    `asset_manager.py`) raises deliberately. A sibling hierarchy to the
    generation-side errors above, not a replacement for them — generating a
    `GeneratedReport` and exporting it to a concrete format are distinct
    pipeline stages with distinct, documented failure modes."""

    code = "REPORT_EXPORT_ERROR"


class UnsupportedExportFormatError(ReportExportError):
    """A `ReportFormat` was requested that `export_manager.py`'s renderer
    registry has no renderer for — should be unreachable for any real
    `ReportFormat` member (the registry is exhaustive over the enum,
    enforced by a unit test), guarded explicitly rather than a bare
    `KeyError`, mirroring `UnknownReportTypeError`'s identical shape."""

    code = "UNSUPPORTED_EXPORT_FORMAT"


class UnknownThemeError(ReportExportError):
    """A theme name was requested that isn't a registered built-in preset
    (`theme.BUILT_IN_THEMES`)."""

    code = "UNKNOWN_THEME"


class OversizedReportExportError(ReportExportError):
    """The `GeneratedReport` handed to `export_manager.ExportManager.export`
    exceeds the configured maximum section/content size — the
    resource-exhaustion guard for export/rendering, mirroring
    `OversizedReportInputError`'s identical reasoning applied to the export
    stage instead of the generation stage."""

    code = "OVERSIZED_REPORT_EXPORT"


class TemplateRenderError(ReportExportError):
    """`template_engine.ReportTemplateEngine.render` failed — a genuine
    Jinja2 template error (never user-controlled: only fixed, trusted
    template files under `core/reporting/templates/` are ever rendered, and
    all case data is passed as escaped context variables, never as template
    source — the structural template-injection defense documented in
    `template_engine.py`)."""

    code = "TEMPLATE_RENDER_ERROR"


class AssetEmbeddingError(ReportExportError):
    """`asset_manager.AssetManager` was asked to embed an asset (a logo, a
    rendered chart image) that is oversized or not a supported image
    format."""

    code = "ASSET_EMBEDDING_ERROR"


class ChartRenderingError(ReportExportError):
    """`chart_image_encoder.ChartImageEncoder.encode` failed to rasterize a
    Plotly figure (e.g. the Kaleido/Chrome backend is unavailable in this
    deployment). Always recoverable: `pdf_renderer.py`/`docx_renderer.py`
    catch this and omit the affected chart with a documented placeholder
    note, never aborting the whole export (constitution §1.7)."""

    code = "CHART_RENDERING_ERROR"
