"""`ReportGenerationMetricsCollector` — reports generated, sections
generated/skipped, failures, processing time. Mirrors
`core.incident_response.metrics.IncidentResponseMetricsCollector`'s
"construct one per process or one per test" shape; self-contained (no
`core/graph` subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel


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
