"""Linux Security Analysis Framework observability — attempt/success/
degraded counters and category distributions, mirroring
`core.vulnerabilities.metrics.VulnerabilityMetricsCollector`'s shape exactly.

Self-contained — does not subscribe to `core.graph.events.EventBus`;
`core/linux_security` is a leaf layer that must never import `core/graph`
(docs/dependency-rules.md rule 5, extended by docs/adr/0018 point 1).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalysisStats(BaseModel):
    """Aggregate counters for one analysis run."""

    attempts: int = 0
    successes: int = 0
    degraded: int = 0
    total_candidates: int = 0
    total_skipped_records: int = 0

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts


class LinuxSecurityMetricsSnapshot(BaseModel):
    """Point-in-time export — category/severity distributions plus run
    stats."""

    stats: AnalysisStats = Field(default_factory=AnalysisStats)
    candidate_counts_by_category: dict[str, int] = Field(default_factory=dict)
    candidate_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    rejected_count: int = 0


class LinuxSecurityMetricsCollector:
    """Construct one per process or one per test for isolation — matches
    `core.vulnerabilities.metrics.VulnerabilityMetricsCollector`'s "one per
    owning component" convention."""

    def __init__(self) -> None:
        self._stats = AnalysisStats()
        self._counts_by_category: dict[str, int] = {}
        self._counts_by_severity: dict[str, int] = {}
        self._rejected_count = 0

    def record_run(self, *, succeeded: bool, candidate_count: int, skipped_records: int) -> None:
        self._stats.attempts += 1
        self._stats.total_candidates += candidate_count
        self._stats.total_skipped_records += skipped_records
        if succeeded:
            self._stats.successes += 1
        else:
            self._stats.degraded += 1

    def record_candidate(self, *, category: str, severity: str) -> None:
        self._counts_by_category[category] = self._counts_by_category.get(category, 0) + 1
        self._counts_by_severity[severity] = self._counts_by_severity.get(severity, 0) + 1

    def record_rejected(self) -> None:
        self._rejected_count += 1

    def snapshot(self) -> LinuxSecurityMetricsSnapshot:
        return LinuxSecurityMetricsSnapshot(
            stats=self._stats.model_copy(),
            candidate_counts_by_category=dict(self._counts_by_category),
            candidate_counts_by_severity=dict(self._counts_by_severity),
            rejected_count=self._rejected_count,
        )
