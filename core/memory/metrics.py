"""Memory Layer observability: retrieval timing, cache/hit-miss counters,
lifecycle event counts.

Deliberately self-contained — `core/graph/metrics.py`'s `MetricsCollector`
subscribes to `core.graph.events.EventBus`, but `core/memory` is a leaf
layer that must never import `core/graph` (docs/dependency-rules.md rule 5
extended: leaves never call up). This module is the memory-layer-local
equivalent: a plain, explicit, injectable collector, not ambient global
state (constitution §2).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from pydantic import BaseModel


class MemoryMetrics(BaseModel):
    """Aggregate counters for one `MemoryMetricsCollector` instance's
    lifetime."""

    hits: int = 0
    misses: int = 0
    writes: int = 0
    evictions: int = 0
    retrieval_count: int = 0
    total_retrieval_ms: float = 0.0

    @property
    def average_retrieval_ms(self) -> float:
        if self.retrieval_count == 0:
            return 0.0
        return self.total_retrieval_ms / self.retrieval_count

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total


class MemoryMetricsCollector:
    """Construct one per `MemoryManager` instance (or one per test) — never
    a process-wide singleton, since metrics are meaningfully scoped to
    whichever memory manager they're measuring, matching
    `core.graph.metrics.MetricsCollector`'s "one per workflow run" rule."""

    def __init__(self) -> None:
        self._metrics = MemoryMetrics()

    def snapshot(self) -> MemoryMetrics:
        return self._metrics.model_copy()

    def record_hit(self) -> None:
        self._metrics.hits += 1

    def record_miss(self) -> None:
        self._metrics.misses += 1

    def record_write(self) -> None:
        self._metrics.writes += 1

    def record_eviction(self, count: int = 1) -> None:
        self._metrics.evictions += count

    @contextmanager
    def time_retrieval(self) -> Iterator[None]:
        """Wrap a retrieval call to record its duration and count it,
        regardless of whether it hit or missed (call `record_hit`/
        `record_miss` separately inside the `with` block)."""
        started = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            self._metrics.retrieval_count += 1
            self._metrics.total_retrieval_ms += elapsed_ms
