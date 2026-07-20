"""Vulnerability Assessment Framework observability — per-extractor attempt/
success/degraded counters and timing, mirroring
`core.threat_intel.metrics.ThreatIntelMetricsCollector`'s shape exactly.

Self-contained — does not subscribe to `core.graph.events.EventBus`;
`core/vulnerabilities` is a leaf layer that must never import `core/graph`
(docs/dependency-rules.md rule 5, extended by docs/adr/0017 point 1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from core.vulnerabilities.extractor import ExtractorRunResult


class ExtractionStats(BaseModel):
    """Aggregate counters for one extractor name."""

    attempts: int = 0
    successes: int = 0
    degraded: int = 0
    total_candidates: int = 0
    total_duration_ms: float = 0.0

    @property
    def average_duration_ms(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.total_duration_ms / self.attempts

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts


class VulnerabilityMetricsSnapshot(BaseModel):
    """Point-in-time export of every extractor's `ExtractionStats`, keyed
    by extractor name, plus severity/detection-source distributions."""

    by_extractor: dict[str, ExtractionStats] = Field(default_factory=dict)
    vulnerability_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    vulnerability_counts_by_source: dict[str, int] = Field(default_factory=dict)
    dedup_merge_count: int = 0
    rejected_count: int = 0


class VulnerabilityMetricsCollector:
    """Construct one per process (see `default_vulnerability_metrics`) or
    one per test for isolation — matches
    `core.parsers.metrics.ParserMetricsCollector`'s "one per owning
    component" convention."""

    def __init__(self) -> None:
        self._by_extractor: dict[str, ExtractionStats] = {}
        self._counts_by_severity: dict[str, int] = {}
        self._counts_by_source: dict[str, int] = {}
        self._dedup_merge_count = 0
        self._rejected_count = 0

    def record_run(self, extractor_name: str, run_result: ExtractorRunResult) -> None:
        stats = self._by_extractor.setdefault(extractor_name, ExtractionStats())
        stats.attempts += 1
        stats.total_duration_ms += run_result.duration_ms
        stats.total_candidates += run_result.candidate_count
        if run_result.succeeded:
            stats.successes += 1
        else:
            stats.degraded += 1

    def record_vulnerability(self, *, severity: str, detection_source: str) -> None:
        self._counts_by_severity[severity] = self._counts_by_severity.get(severity, 0) + 1
        self._counts_by_source[detection_source] = (
            self._counts_by_source.get(detection_source, 0) + 1
        )

    def record_dedup_merge(self) -> None:
        self._dedup_merge_count += 1

    def record_rejected(self) -> None:
        self._rejected_count += 1

    def snapshot(self) -> VulnerabilityMetricsSnapshot:
        return VulnerabilityMetricsSnapshot(
            by_extractor={name: stats.model_copy() for name, stats in self._by_extractor.items()},
            vulnerability_counts_by_severity=dict(self._counts_by_severity),
            vulnerability_counts_by_source=dict(self._counts_by_source),
            dedup_merge_count=self._dedup_merge_count,
            rejected_count=self._rejected_count,
        )

    def stats_for(self, extractor_name: str) -> ExtractionStats:
        return self._by_extractor.get(extractor_name, ExtractionStats())
