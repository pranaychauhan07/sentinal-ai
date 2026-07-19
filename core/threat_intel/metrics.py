"""Threat Intelligence Layer observability — per-extractor attempt/success/
degraded counters and timing, mirroring `core.parsers.metrics.
ParserMetricsCollector`'s shape exactly.

Self-contained — does not subscribe to `core.graph.events.EventBus`;
`core/threat_intel` is a leaf layer that must never import `core/graph`
(docs/dependency-rules.md rule 5, extended by docs/adr/0012 point 1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from core.threat_intel.base import ExtractorRunResult


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


class ThreatIntelMetricsSnapshot(BaseModel):
    """Point-in-time export of every extractor's `ExtractionStats`, keyed
    by extractor name."""

    by_extractor: dict[str, ExtractionStats] = Field(default_factory=dict)
    rule_match_counts: dict[str, int] = Field(default_factory=dict)
    ioc_counts_by_type: dict[str, int] = Field(default_factory=dict)


class ThreatIntelMetricsCollector:
    """Construct one per process (see `default_threat_intel_metrics`) or one
    per test for isolation — matches `core.parsers.metrics.
    ParserMetricsCollector`'s "one per owning component" convention."""

    def __init__(self) -> None:
        self._by_extractor: dict[str, ExtractionStats] = {}
        self._rule_match_counts: dict[str, int] = {}
        self._ioc_counts_by_type: dict[str, int] = {}

    def record_run(self, extractor_name: str, run_result: ExtractorRunResult) -> None:
        stats = self._by_extractor.setdefault(extractor_name, ExtractionStats())
        stats.attempts += 1
        stats.total_duration_ms += run_result.duration_ms
        stats.total_candidates += run_result.candidate_count
        if run_result.succeeded:
            stats.successes += 1
        else:
            stats.degraded += 1

    def record_rule_match(self, rule_id: str) -> None:
        self._rule_match_counts[rule_id] = self._rule_match_counts.get(rule_id, 0) + 1

    def record_ioc(self, ioc_type: str) -> None:
        self._ioc_counts_by_type[ioc_type] = self._ioc_counts_by_type.get(ioc_type, 0) + 1

    def snapshot(self) -> ThreatIntelMetricsSnapshot:
        return ThreatIntelMetricsSnapshot(
            by_extractor={name: stats.model_copy() for name, stats in self._by_extractor.items()},
            rule_match_counts=dict(self._rule_match_counts),
            ioc_counts_by_type=dict(self._ioc_counts_by_type),
        )

    def stats_for(self, extractor_name: str) -> ExtractionStats:
        return self._by_extractor.get(extractor_name, ExtractionStats())
