"""`IncidentResponseMetricsCollector` — findings considered, recommendations
generated, skipped/malformed records, processing time. Mirrors
`core.linux_advisor.metrics.LinuxAdvisorMetricsCollector`'s "construct one
per process or one per test" shape; self-contained (no `core/graph`
subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel


class IncidentResponseMetricsSnapshot(BaseModel):
    findings_considered: int = 0
    recommendations_generated: int = 0
    recommendations_deduplicated: int = 0
    skipped_record_count: int = 0
    failure_count: int = 0
    total_processing_ms: float = 0.0


class IncidentResponseMetricsCollector:
    def __init__(self) -> None:
        self._findings_considered = 0
        self._recommendations_generated = 0
        self._recommendations_deduplicated = 0
        self._skipped_record_count = 0
        self._failure_count = 0
        self._total_processing_ms = 0.0

    def record_finding_considered(self) -> None:
        self._findings_considered += 1

    def record_recommendation_generated(self) -> None:
        self._recommendations_generated += 1

    def record_recommendations_deduplicated(self, count: int) -> None:
        self._recommendations_deduplicated += count

    def record_skipped_record(self) -> None:
        self._skipped_record_count += 1

    def record_failure(self) -> None:
        self._failure_count += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> IncidentResponseMetricsSnapshot:
        return IncidentResponseMetricsSnapshot(
            findings_considered=self._findings_considered,
            recommendations_generated=self._recommendations_generated,
            recommendations_deduplicated=self._recommendations_deduplicated,
            skipped_record_count=self._skipped_record_count,
            failure_count=self._failure_count,
            total_processing_ms=self._total_processing_ms,
        )
