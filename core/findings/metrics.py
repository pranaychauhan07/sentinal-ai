"""Finding & MITRE mapping engine observability — mirroring
`core.threat_intel.metrics.ThreatIntelMetricsCollector`'s shape exactly.

Self-contained — does not subscribe to `core.graph.events.EventBus`;
`core/findings` is a leaf layer that must never import `core/graph`
(docs/dependency-rules.md rule 5, extended by docs/adr/0013 point 2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from core.findings.base import MappingRunResult


class MappingStats(BaseModel):
    """Aggregate counters for one mapping engine name."""

    attempts: int = 0
    successes: int = 0
    degraded: int = 0
    total_mappings: int = 0
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


class FindingsMetricsSnapshot(BaseModel):
    """Point-in-time export of every mapping engine's `MappingStats`, plus
    Finding-level and dedup-level counters."""

    by_engine: dict[str, MappingStats] = Field(default_factory=dict)
    findings_generated: int = 0
    findings_merged: int = 0
    duplicate_candidates_rejected: int = 0
    technique_match_counts: dict[str, int] = Field(default_factory=dict)


class FindingsMetricsCollector:
    """Construct one per process (or one per test for isolation) — matches
    `core.threat_intel.metrics.ThreatIntelMetricsCollector`'s convention."""

    def __init__(self) -> None:
        self._by_engine: dict[str, MappingStats] = {}
        self._findings_generated = 0
        self._findings_merged = 0
        self._duplicate_candidates_rejected = 0
        self._technique_match_counts: dict[str, int] = {}

    def record_run(self, engine_name: str, run_result: MappingRunResult) -> None:
        stats = self._by_engine.setdefault(engine_name, MappingStats())
        stats.attempts += 1
        stats.total_duration_ms += run_result.duration_ms
        stats.total_mappings += run_result.mapping_count
        if run_result.succeeded:
            stats.successes += 1
        else:
            stats.degraded += 1

    def record_technique_match(self, technique_id: str) -> None:
        self._technique_match_counts[technique_id] = (
            self._technique_match_counts.get(technique_id, 0) + 1
        )

    def record_finding_generated(self) -> None:
        self._findings_generated += 1

    def record_finding_merged(self) -> None:
        self._findings_merged += 1

    def record_duplicate_rejected(self) -> None:
        self._duplicate_candidates_rejected += 1

    def snapshot(self) -> FindingsMetricsSnapshot:
        return FindingsMetricsSnapshot(
            by_engine={name: stats.model_copy() for name, stats in self._by_engine.items()},
            findings_generated=self._findings_generated,
            findings_merged=self._findings_merged,
            duplicate_candidates_rejected=self._duplicate_candidates_rejected,
            technique_match_counts=dict(self._technique_match_counts),
        )

    def stats_for(self, engine_name: str) -> MappingStats:
        return self._by_engine.get(engine_name, MappingStats())
