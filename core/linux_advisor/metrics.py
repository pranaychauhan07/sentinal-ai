"""`LinuxAdvisorMetricsCollector` — commands analyzed, permission strings
analyzed, rule matches by category/id, processing time, failure counts.
Mirrors `core.vulnerabilities.metrics.VulnerabilityMetricsCollector`'s
"construct one per process or one per test" shape; self-contained (no
`core/graph` subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class LinuxAdvisorMetricsSnapshot(BaseModel):
    commands_analyzed: int = 0
    permissions_analyzed: int = 0
    rule_matches_by_id: dict[str, int] = Field(default_factory=dict)
    failure_count: int = 0
    total_processing_ms: float = 0.0


class LinuxAdvisorMetricsCollector:
    def __init__(self) -> None:
        self._commands_analyzed = 0
        self._permissions_analyzed = 0
        self._rule_matches_by_id: dict[str, int] = {}
        self._failure_count = 0
        self._total_processing_ms = 0.0

    def record_command_analyzed(self) -> None:
        self._commands_analyzed += 1

    def record_permission_analyzed(self) -> None:
        self._permissions_analyzed += 1

    def record_rule_match(self, rule_id: str) -> None:
        self._rule_matches_by_id[rule_id] = self._rule_matches_by_id.get(rule_id, 0) + 1

    def record_failure(self) -> None:
        self._failure_count += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> LinuxAdvisorMetricsSnapshot:
        return LinuxAdvisorMetricsSnapshot(
            commands_analyzed=self._commands_analyzed,
            permissions_analyzed=self._permissions_analyzed,
            rule_matches_by_id=dict(self._rule_matches_by_id),
            failure_count=self._failure_count,
            total_processing_ms=self._total_processing_ms,
        )
