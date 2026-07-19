"""Parser Layer observability: per-parser attempt/success/failure counters
and timing, mirroring `core/memory/metrics.py::MemoryMetricsCollector`'s
shape exactly.

Deliberately self-contained — does not subscribe to `core.graph.events.
EventBus`. `core/parsers` is a leaf layer that must never import
`core/graph` (docs/dependency-rules.md rule 5); this is the parser-layer-local
equivalent, an explicit, injectable collector, never ambient global state
(constitution §2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from core.parsers.base import ParserRunResult


class ParserStats(BaseModel):
    """Aggregate counters for one parser name."""

    attempts: int = 0
    successes: int = 0
    degraded: int = 0
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


class ParserMetricsSnapshot(BaseModel):
    """Point-in-time export of every parser's `ParserStats`, keyed by
    parser name — the payload a future `/metrics`-style endpoint or a test
    assertion reads."""

    by_parser: dict[str, ParserStats] = Field(default_factory=dict)


class ParserMetricsCollector:
    """Construct one per process (see `default_parser_metrics`) or one per
    test for isolation — matches `core.memory.metrics.MemoryMetricsCollector`'s
    "one per owning component" convention."""

    def __init__(self) -> None:
        self._by_parser: dict[str, ParserStats] = {}

    def record_run(self, parser_name: str, run_result: ParserRunResult) -> None:
        stats = self._by_parser.setdefault(parser_name, ParserStats())
        stats.attempts += 1
        stats.total_duration_ms += run_result.duration_ms
        if run_result.succeeded:
            stats.successes += 1
        else:
            stats.degraded += 1

    def snapshot(self) -> ParserMetricsSnapshot:
        return ParserMetricsSnapshot(
            by_parser={name: stats.model_copy() for name, stats in self._by_parser.items()}
        )

    def stats_for(self, parser_name: str) -> ParserStats:
        return self._by_parser.get(parser_name, ParserStats())
