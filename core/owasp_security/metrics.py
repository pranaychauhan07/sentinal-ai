"""``SastMetricsCollector`` — files/lines analyzed, rule matches by id,
processing time, failure counts. Mirrors
`core.owasp_web.metrics.WebSecurityMetricsCollector`'s "construct one per
process or one per test" shape; self-contained (no `core/graph`
subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SastMetricsSnapshot(BaseModel):
    files_analyzed: int = 0
    lines_analyzed: int = 0
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    rule_matches_by_id: dict[str, int] = Field(default_factory=dict)
    failure_count: int = 0
    total_processing_ms: float = 0.0


class SastMetricsCollector:
    def __init__(self) -> None:
        self._files_analyzed = 0
        self._lines_analyzed = 0
        self._findings_by_category: dict[str, int] = {}
        self._rule_matches_by_id: dict[str, int] = {}
        self._failure_count = 0
        self._total_processing_ms = 0.0

    def record_file_analyzed(self, line_count: int) -> None:
        self._files_analyzed += 1
        self._lines_analyzed += line_count

    def record_finding(self, category: str) -> None:
        self._findings_by_category[category] = self._findings_by_category.get(category, 0) + 1

    def record_rule_match(self, rule_id: str) -> None:
        self._rule_matches_by_id[rule_id] = self._rule_matches_by_id.get(rule_id, 0) + 1

    def record_failure(self) -> None:
        self._failure_count += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> SastMetricsSnapshot:
        return SastMetricsSnapshot(
            files_analyzed=self._files_analyzed,
            lines_analyzed=self._lines_analyzed,
            findings_by_category=dict(self._findings_by_category),
            rule_matches_by_id=dict(self._rule_matches_by_id),
            failure_count=self._failure_count,
            total_processing_ms=self._total_processing_ms,
        )
