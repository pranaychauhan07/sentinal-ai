"""`ReportGenerationMetricsCollector` — reports generated, sections
generated/skipped, failures, processing time. Mirrors
`core.incident_response.metrics.IncidentResponseMetricsCollector`'s
"construct one per process or one per test" shape; self-contained (no
`core/graph` subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReportGenerationMetricsSnapshot(BaseModel):
    reports_generated: int = 0
    sections_generated: int = 0
    sections_failed: int = 0
    failure_count: int = 0
    total_processing_ms: float = 0.0


class ReportGenerationMetricsCollector:
    def __init__(self) -> None:
        self._reports_generated = 0
        self._sections_generated = 0
        self._sections_failed = 0
        self._failure_count = 0
        self._total_processing_ms = 0.0

    def record_report_generated(self) -> None:
        self._reports_generated += 1

    def record_section_generated(self) -> None:
        self._sections_generated += 1

    def record_section_failed(self) -> None:
        self._sections_failed += 1

    def record_failure(self) -> None:
        self._failure_count += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> ReportGenerationMetricsSnapshot:
        return ReportGenerationMetricsSnapshot(
            reports_generated=self._reports_generated,
            sections_generated=self._sections_generated,
            sections_failed=self._sections_failed,
            failure_count=self._failure_count,
            total_processing_ms=self._total_processing_ms,
        )


class ReportExportMetricsSnapshot(BaseModel):
    exports_generated: int = 0
    exports_failed: int = 0
    exports_by_format: dict[str, int] = Field(default_factory=dict)
    failures_by_format: dict[str, int] = Field(default_factory=dict)
    total_processing_ms: float = 0.0


class ReportExportMetricsCollector:
    """Export/rendering-stage counterpart to
    `ReportGenerationMetricsCollector` above — a distinct class (not reused
    fields on the generation collector) since export tracks a different
    dimension (per-*format* counts/timing/failures: PDF vs. HTML vs. DOCX
    rendering cost varies enormously) from section-generation observability.
    Living in this same module rather than a new file since both are
    `core/reporting`'s one observability surface (constitution §1.6)."""

    def __init__(self) -> None:
        self._exports_generated = 0
        self._exports_failed = 0
        self._exports_by_format: dict[str, int] = {}
        self._failures_by_format: dict[str, int] = {}
        self._total_processing_ms = 0.0

    def record_export_generated(self, export_format: str) -> None:
        self._exports_generated += 1
        self._exports_by_format[export_format] = self._exports_by_format.get(export_format, 0) + 1

    def record_export_failed(self, export_format: str) -> None:
        self._exports_failed += 1
        self._failures_by_format[export_format] = self._failures_by_format.get(export_format, 0) + 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> ReportExportMetricsSnapshot:
        return ReportExportMetricsSnapshot(
            exports_generated=self._exports_generated,
            exports_failed=self._exports_failed,
            exports_by_format=dict(self._exports_by_format),
            failures_by_format=dict(self._failures_by_format),
            total_processing_ms=self._total_processing_ms,
        )
