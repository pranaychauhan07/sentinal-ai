"""`build_investigation_memory_context` — the Memory Agent's "Memory
Service" (ADR-0028): deterministic ranking/threshold/dedup aggregation over
`LongTermMemoryManager`'s per-category retrieval, kept in `core/memory`
(never `core/tools`, which `docs/dependency-rules.md` rule 5 explicitly
forbids from importing `core/memory`) so it can be called directly by
`core/services/case_service.py` (rule 4d) the same way `long_term.py`/
`manager.py` already are.

This module performs no embedding/vector-store I/O itself — it composes
`LongTermMemory.find_similar_in_case`/`find_similar_excluding_case`, which are
already advisory (ADR-0006: a backend failure degrades to `[]`, never
raises). What this module adds on top: per-category `top_k` truncation, a
`min_similarity` confidence floor, and cross-call deduplication (the same
`(case_id, finding_id)` pair surfacing from more than one category query —
possible since `find_similar_in_case`/`find_similar_excluding_case` are
independent calls, unlike a single backend query with one result set).

Always advisory as a whole: any single category's retrieval failing (already
caught inside `LongTermMemoryManager`) never prevents the others from
returning results; this function itself never raises.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import UUID

from core.memory.interfaces import LongTermMemory, SimilarResult
from core.memory.long_term import RECORD_CATEGORIES

#: `RECORD_CATEGORIES` minus nothing — every category `LongTermMemoryManager`
#: recognizes is queried by default. A caller may narrow this (e.g. a future
#: on-demand "similar findings only" panel) via `MemoryRetrievalConfig.categories`.
DEFAULT_CATEGORIES: tuple[str, ...] = RECORD_CATEGORIES


@dataclass(frozen=True)
class MemoryRetrievalConfig:
    """Configurable retrieval strategy (task requirement: "Support
    configurable retrieval strategies"). A plain, internal `dataclass`
    (constitution §2: reserved for simple, non-validated, function-local
    carriers) rather than a `BaseModel` — this never crosses a `core/agents`/
    `core/tools`/API boundary as a public contract; those layers only ever
    see the already-computed `RawMemoryContext` below."""

    #: Vector-memory categories to query. Defaults to every category
    #: `LongTermMemoryManager` recognizes.
    categories: tuple[str, ...] = DEFAULT_CATEGORIES
    #: Max results kept per category after ranking/threshold/dedup.
    top_k_per_category: int = 5
    #: Results scoring below this similarity are dropped — "Confidence
    #: thresholds" (task requirement). `SimilarResult.score` is already a
    #: cosine similarity in `[0.0, 1.0]` (`ChromaVectorStore`/
    #: `InMemoryVectorStore`), so this is directly comparable.
    min_similarity: float = 0.35
    #: Results are over-fetched by this multiplier before threshold/dedup so
    #: truncation to `top_k_per_category` still has enough surviving
    #: candidates to choose from.
    overfetch_multiplier: int = 3


@dataclass(frozen=True)
class RetrievalOutcome:
    """One category's retrieval outcome — raw enough for the Memory Agent's
    tool to compute its own typed `RetrievalMetrics` from, without this
    module needing to know about that agent-layer shape."""

    category: str
    results: tuple[SimilarResult, ...]
    raw_candidate_count: int
    below_threshold_dropped: int
    duplicate_dropped: int
    latency_ms: float
    degraded: bool
    error: str | None = None


@dataclass(frozen=True)
class RawMemoryContext:
    """This function's full output — one `RetrievalOutcome` per queried
    category, plus the overall query text and total latency. `core/services/
    case_service.py` reduces this to a plain dict for
    `CaseInvestigationState.memory_context_record`; nothing here is itself
    written directly onto graph state (constitution §2: dataclasses never
    cross a public module boundary as-is when a typed, validated contract is
    expected downstream — the *reduction* to a dict is that boundary)."""

    query_text: str
    outcomes: tuple[RetrievalOutcome, ...]
    total_latency_ms: float
    degraded: bool = False

    def outcome_for(self, category: str) -> RetrievalOutcome | None:
        return next((o for o in self.outcomes if o.category == category), None)


def _dedupe(results: list[SimilarResult]) -> tuple[list[SimilarResult], int]:
    """Drops a `(case_id, finding_id)` pair already seen earlier in
    `results` (highest-scored occurrence wins, since callers rank before
    dedup) — the cross-call duplicate scenario this module exists to guard
    against (see module docstring)."""
    seen: set[tuple[UUID, UUID]] = set()
    deduped: list[SimilarResult] = []
    dropped = 0
    for result in results:
        key = (result.case_id, result.finding_id)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(result)
    return deduped, dropped


async def _retrieve_category(
    *,
    long_term_memory: LongTermMemory,
    category: str,
    query_text: str,
    case_id: UUID,
    config: MemoryRetrievalConfig,
) -> RetrievalOutcome:
    started = time.perf_counter()
    try:
        # "Similar past investigations" (blueprint §7) is the `case_summary`
        # category's defined meaning; every category uses the same
        # cross-case-excluding-this-case retrieval — `LongTermMemoryManager`'s
        # own `find_similar_cases`/`find_similar_findings`/... convenience
        # wrappers are exactly this call pre-bound to one `category`.
        raw = await long_term_memory.find_similar_excluding_case(
            query_text,
            exclude_case_id=case_id,
            limit=config.top_k_per_category * config.overfetch_multiplier,
            category=category,
        )
    except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the caller
        latency_ms = (time.perf_counter() - started) * 1000
        return RetrievalOutcome(
            category=category,
            results=(),
            raw_candidate_count=0,
            below_threshold_dropped=0,
            duplicate_dropped=0,
            latency_ms=latency_ms,
            degraded=True,
            error=str(exc),
        )

    raw_count = len(raw)
    ranked = sorted(raw, key=lambda r: r.score, reverse=True)
    above_threshold = [r for r in ranked if r.score >= config.min_similarity]
    below_threshold_dropped = len(ranked) - len(above_threshold)
    deduped, duplicate_dropped = _dedupe(above_threshold)
    top = deduped[: config.top_k_per_category]
    latency_ms = (time.perf_counter() - started) * 1000
    return RetrievalOutcome(
        category=category,
        results=tuple(top),
        raw_candidate_count=raw_count,
        below_threshold_dropped=below_threshold_dropped,
        duplicate_dropped=duplicate_dropped,
        latency_ms=latency_ms,
        degraded=False,
    )


async def build_investigation_memory_context(
    query_text: str,
    *,
    case_id: UUID,
    long_term_memory: LongTermMemory,
    config: MemoryRetrievalConfig | None = None,
) -> RawMemoryContext:
    """Queries every configured category, ranks/thresholds/dedupes each
    independently, and returns the combined raw result. An empty
    `query_text` (no evidence/finding signal yet — e.g. a case whose only
    upload produced zero IOCs/findings) short-circuits to an all-empty,
    `degraded=True` result without ever calling the backend — never a
    meaningless all-zero-vector query.
    """
    resolved_config = config or MemoryRetrievalConfig()
    if not query_text.strip():
        return RawMemoryContext(
            query_text=query_text, outcomes=(), total_latency_ms=0.0, degraded=True
        )

    started = time.perf_counter()
    outcomes = [
        await _retrieve_category(
            long_term_memory=long_term_memory,
            category=category,
            query_text=query_text,
            case_id=case_id,
            config=resolved_config,
        )
        for category in resolved_config.categories
    ]
    total_latency_ms = (time.perf_counter() - started) * 1000
    return RawMemoryContext(
        query_text=query_text,
        outcomes=tuple(outcomes),
        total_latency_ms=total_latency_ms,
        degraded=any(o.degraded for o in outcomes),
    )
