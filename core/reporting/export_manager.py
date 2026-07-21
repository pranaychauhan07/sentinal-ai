"""Export Manager — the task's named "Export Manager".

The one place that dispatches a `GeneratedReport` to the correct renderer
for a requested `ReportFormat`, wraps the result in a typed `ExportedReport`
(bytes + media type + filename — everything `core/services/
report_export_service.py`/`apps/api/routers/report_export.py` need to
serve a download, never a bare `bytes` return value crossing a public
function boundary), and is the one place the "oversized export" guard
(constitution §10) and export-specific audit/metrics events are recorded,
mirroring `report_engine.ReportGenerationEngine`'s identical
orchestrator shape on the generation side.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from core.reporting.asset_manager import AssetManager
from core.reporting.audit import (
    AuditAction,
    log_report_export_audit_event,
    timed_execution,
)
from core.reporting.chart_image_encoder import ChartImageEncoder, KaleidoChartImageEncoder
from core.reporting.docx_renderer import DOCXReportRenderer
from core.reporting.exceptions import OversizedReportExportError, UnsupportedExportFormatError
from core.reporting.html_renderer import HTMLReportRenderer
from core.reporting.markdown_renderer import MarkdownReportRenderer
from core.reporting.metrics import ReportExportMetricsCollector
from core.reporting.models import GeneratedReport, ReportFormat
from core.reporting.pdf_renderer import PDFReportRenderer
from core.reporting.theme import ReportTheme, resolve_theme

#: Ceiling on the serialized size of the `GeneratedReport` this manager will
#: attempt to render — the resource-exhaustion guard for export/rendering
#: (constitution §10, "oversized exports"), mirroring `report_engine.
#: DEFAULT_MAX_RECORDS_PER_REPORT`'s identical reasoning applied to the
#: export stage, measured in serialized bytes here since rendering cost
#: (especially PDF/DOCX flowable construction) scales with content size,
#: not record count.
DEFAULT_MAX_REPORT_EXPORT_BYTES = 25 * 1024 * 1024  # 25 MiB

_MEDIA_TYPES: dict[ReportFormat, str] = {
    ReportFormat.PDF: "application/pdf",
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ReportFormat.JSON: "application/json",
    ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_EXTENSIONS: dict[ReportFormat, str] = {
    ReportFormat.PDF: "pdf",
    ReportFormat.HTML: "html",
    ReportFormat.MARKDOWN: "md",
    ReportFormat.JSON: "json",
    ReportFormat.DOCX: "docx",
}


class ExportedReport(BaseModel):
    """`ExportManager.export`'s output — the one typed shape every caller
    (service, API route, test) works with, never a bare `bytes` value."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    export_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    report_id: uuid.UUID
    case_id: str
    format: ReportFormat
    filename: str
    media_type: str
    content: bytes
    size_bytes: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def _filename_for(report: GeneratedReport, export_format: ReportFormat) -> str:
    extension = _EXTENSIONS[export_format]
    safe_case_id = report.case_id.replace("/", "_").replace("\\", "_")
    return f"{safe_case_id}_{report.report_type.value}.{extension}"


class ExportManager:
    def __init__(
        self,
        *,
        max_export_bytes: int = DEFAULT_MAX_REPORT_EXPORT_BYTES,
        html_renderer: HTMLReportRenderer | None = None,
        markdown_renderer: MarkdownReportRenderer | None = None,
        pdf_renderer: PDFReportRenderer | None = None,
        docx_renderer: DOCXReportRenderer | None = None,
        chart_image_encoder: ChartImageEncoder | None = None,
        asset_manager: AssetManager | None = None,
        metrics: ReportExportMetricsCollector | None = None,
    ) -> None:
        self._max_export_bytes = max_export_bytes
        encoder = chart_image_encoder or KaleidoChartImageEncoder()
        assets = asset_manager or AssetManager()
        self._html_renderer = html_renderer or HTMLReportRenderer()
        self._markdown_renderer = markdown_renderer or MarkdownReportRenderer(
            asset_manager=assets, chart_image_encoder=encoder
        )
        self._pdf_renderer = pdf_renderer or PDFReportRenderer(
            asset_manager=assets, chart_image_encoder=encoder
        )
        self._docx_renderer = docx_renderer or DOCXReportRenderer(
            asset_manager=assets, chart_image_encoder=encoder
        )
        self._metrics = metrics or ReportExportMetricsCollector()

    def supported_formats(self) -> tuple[ReportFormat, ...]:
        return tuple(_MEDIA_TYPES)

    def export(
        self,
        report: GeneratedReport,
        export_format: ReportFormat,
        *,
        theme: ReportTheme | str | None = None,
        include_charts: bool = True,
    ) -> ExportedReport:
        if export_format not in _MEDIA_TYPES:
            requested = getattr(export_format, "value", export_format)
            raise UnsupportedExportFormatError(
                f"'{requested}' has no registered renderer.",
                details={"format": str(requested), "supported": [f.value for f in _MEDIA_TYPES]},
            )

        estimated_size = len(report.model_dump_json().encode("utf-8"))
        if estimated_size > self._max_export_bytes:
            log_report_export_audit_event(
                action=AuditAction.OVERSIZED_EXPORT_REJECTED,
                case_id=report.case_id,
                detail=f"{estimated_size} bytes exceeds max {self._max_export_bytes}.",
            )
            raise OversizedReportExportError(
                f"Report of {estimated_size} bytes exceeds the configured export maximum of "
                f"{self._max_export_bytes} bytes.",
                details={"case_id": report.case_id, "size_bytes": estimated_size},
            )

        resolved_theme = resolve_theme(theme)
        with timed_execution(f"export_{export_format.value}") as timing:
            try:
                content = self._render(report, export_format, resolved_theme, include_charts)
            except Exception:
                self._metrics.record_export_failed(export_format.value)
                log_report_export_audit_event(
                    action=AuditAction.EXPORT_FAILED,
                    case_id=report.case_id,
                    detail=f"format={export_format.value}",
                )
                raise

        self._metrics.record_export_generated(export_format.value)
        self._metrics.record_processing_time(timing["duration_ms"])
        log_report_export_audit_event(
            action=AuditAction.EXPORT_GENERATED,
            case_id=report.case_id,
            detail=f"format={export_format.value}, size_bytes={len(content)}",
        )

        return ExportedReport(
            report_id=report.report_id,
            case_id=report.case_id,
            format=export_format,
            filename=_filename_for(report, export_format),
            media_type=_MEDIA_TYPES[export_format],
            content=content,
            size_bytes=len(content),
        )

    def _render(
        self,
        report: GeneratedReport,
        export_format: ReportFormat,
        theme: ReportTheme,
        include_charts: bool,
    ) -> bytes:
        if export_format is ReportFormat.HTML:
            return self._html_renderer.render_bytes(
                report, theme=theme, include_charts=include_charts
            )
        if export_format is ReportFormat.MARKDOWN:
            return self._markdown_renderer.render_bytes(report, include_charts=include_charts)
        if export_format is ReportFormat.PDF:
            return self._pdf_renderer.render(report, theme=theme, include_charts=include_charts)
        if export_format is ReportFormat.DOCX:
            return self._docx_renderer.render(report, theme=theme, include_charts=include_charts)
        if export_format is ReportFormat.JSON:
            return report.model_dump_json(indent=2).encode("utf-8")
        raise UnsupportedExportFormatError(  # pragma: no cover - guarded above, defense in depth
            f"'{export_format.value}' has no registered renderer.",
            details={"format": export_format.value},
        )
