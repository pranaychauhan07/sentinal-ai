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
    #: ADR-0027 — embedding-provider and vector-store call observability,
    #: separate from the generic `retrieval_count`/`total_retrieval_ms`
    #: above (which time the whole `find_similar*` call, not just the
    #: embedding step) so a slow provider vs. a slow vector store are
    #: distinguishable in one metrics snapshot.
    embedding_calls: int = 0
    embedding_failures: int = 0
    total_embedding_ms: float = 0.0
    vector_store_calls: int = 0
    vector_store_failures: int = 0
    total_vector_store_ms: float = 0.0

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

    @property
    def average_embedding_ms(self) -> float:
        if self.embedding_calls == 0:
            return 0.0
        return self.total_embedding_ms / self.embedding_calls

    @property
    def average_vector_store_ms(self) -> float:
        if self.vector_store_calls == 0:
            return 0.0
        return self.total_vector_store_ms / self.vector_store_calls


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

    @contextmanager
    def time_embedding_call(self) -> Iterator[None]:
        """Wrap one `TextEmbedder.embed` call (ADR-0027). On an
        `EmbeddingProviderError` raised inside the block, records a failure
        and re-raises unchanged — this collector only observes, it never
        changes control flow (constitution §1.7's degrade-at-the-call-site
        boundary stays in `long_term.py`, not here)."""
        started = time.perf_counter()
        try:
            yield
        except Exception:
            self._metrics.embedding_failures += 1
            raise
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            self._metrics.embedding_calls += 1
            self._metrics.total_embedding_ms += elapsed_ms

    @contextmanager
    def time_vector_store_call(self) -> Iterator[None]:
        """Wrap one `VectorMemory` backend call (ADR-0027) — same shape as
        `time_embedding_call`, for the storage side of a retrieval/write."""
        started = time.perf_counter()
        try:
            yield
        except Exception:
            self._metrics.vector_store_failures += 1
            raise
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            self._metrics.vector_store_calls += 1
            self._metrics.total_vector_store_ms += elapsed_ms
