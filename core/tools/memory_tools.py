"""`MemoryContextResolutionTool` — blueprint's cross-case Memory Agent's
deterministic resolution tool (ADR-0028).

Never performs retrieval itself — `core.memory.investigation_context.
build_investigation_memory_context` (invoked by `core/services/
case_service.py` before the graph runs; see ADR-0028 §1) already did that.
This tool's job is purely deterministic reconstruction/labeling/aggregation:
turn the already-retrieved, already-ranked/thresholded/deduplicated raw
matches into the typed `MemoryContext` `core.agents.memory_agent.MemoryAgent`
returns, computing a human-readable confidence label and "reason for
retrieval" string per item, and a case-level `RetrievalMetrics` summary.

Stays dict/primitive-shaped on input (`RawSimilarItem`/`RawKnowledgeItem`
below are this module's own local Pydantic models, not imports of
`core.memory.interfaces.SimilarResult`/`core.knowledge.models.
KnowledgeSearchResult`) because `docs/dependency-rules.md` rule 5 forbids
`core/tools` from importing `core/memory` at all — mirroring `vuln_tools.py`/
`owasp_tools.py`'s "no cross-leaf import" precedent, not `mitre_tools.py`'s
(which has an explicit, narrower exception for `core/knowledge` only).
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Confidence-label thresholds — deterministic bucketing of a `[0.0, 1.0]`
#: similarity score into a human-readable label (constitution §1.9: even this
#: small a judgment call is a plain function, never left to LLM phrasing).
HIGH_CONFIDENCE_THRESHOLD = 0.75
MEDIUM_CONFIDENCE_THRESHOLD = 0.5

#: Hard ceiling on total items across every category, defense-in-depth
#: against a misconfigured `MemoryRetrievalConfig.top_k_per_category`
#: producing an oversized prompt/report context (task requirement: "Protect
#: against ... Oversized context").
MAX_TOTAL_ITEMS = 50


def confidence_label(score: float) -> str:
    """Deterministic score -> label bucketing, shared by every item type
    below rather than reimplemented per category."""
    if score >= HIGH_CONFIDENCE_THRESHOLD:
        return "high"
    if score >= MEDIUM_CONFIDENCE_THRESHOLD:
        return "medium"
    return "low"


class RawSimilarItem(BaseModel):
    """One already-retrieved, already-ranked/thresholded vector-memory
    match — this tool's own typed shape (never `core.memory.interfaces.
    SimilarResult`, per this module's docstring)."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    record_id: str
    score: float = Field(ge=0.0, le=1.0)
    excerpt: str = ""
    category: str = "finding"
    recorded_at: str | None = None


class RawKnowledgeItem(BaseModel):
    """One already-retrieved Knowledge Layer search result — this tool's own
    typed shape (never `core.knowledge.models.KnowledgeSearchResult`)."""

    model_config = ConfigDict(frozen=True)

    source_type: str
    document_id: str
    title: str = ""
    content: str = ""
    score: float = Field(ge=0.0, le=1.0)


class CategoryRetrievalMetricsInput(BaseModel):
    """One category's raw retrieval outcome — mirrors
    `core.memory.investigation_context.RetrievalOutcome`'s fields, reduced to
    plain primitives for the same reason every other field on this input
    stays dict/primitive-shaped."""

    model_config = ConfigDict(frozen=True)

    category: str
    raw_candidate_count: int = 0
    below_threshold_dropped: int = 0
    duplicate_dropped: int = 0
    latency_ms: float = 0.0
    degraded: bool = False
    error: str | None = None


class MemoryContextResolutionInput(BaseModel):
    """Everything `build_investigation_memory_context` (plus the
    Knowledge Layer search `case_service.py` runs alongside it) already
    computed, reduced to plain typed lists."""

    model_config = ConfigDict(frozen=True)

    query_text: str = ""
    similar_cases: list[RawSimilarItem] = Field(default_factory=list)
    similar_findings: list[RawSimilarItem] = Field(default_factory=list)
    similar_iocs: list[RawSimilarItem] = Field(default_factory=list)
    similar_mitre_techniques: list[RawSimilarItem] = Field(default_factory=list)
    similar_reports: list[RawSimilarItem] = Field(default_factory=list)
    related_knowledge: list[RawKnowledgeItem] = Field(default_factory=list)
    category_metrics: list[CategoryRetrievalMetricsInput] = Field(default_factory=list)
    knowledge_latency_ms: float = 0.0
    knowledge_error: str | None = None
    total_latency_ms: float = 0.0
    min_similarity: float = 0.0
    top_k_per_category: int = 5
    overall_degraded: bool = False


class SimilarCase(BaseModel):
    """One similar past investigation (blueprint §7's exact phrase) — the
    `case_summary` category, cross-case by construction."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    excerpt: str
    source: str = "long_term_memory:case_summary"
    recorded_at: str | None = None
    reason: str


class SimilarFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    finding_id: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    excerpt: str
    source: str = "long_term_memory:finding"
    recorded_at: str | None = None
    reason: str


class SimilarIOC(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    ioc_record_id: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    excerpt: str
    source: str = "long_term_memory:ioc"
    recorded_at: str | None = None
    reason: str


class SimilarMitreTechnique(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    record_id: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    excerpt: str
    source: str = "long_term_memory:mitre_technique"
    recorded_at: str | None = None
    reason: str


class SimilarReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    report_id: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    excerpt: str
    source: str = "long_term_memory:report"
    recorded_at: str | None = None
    reason: str


class RelatedKnowledge(BaseModel):
    """One relevant knowledge-base document (OWASP/security-playbook/
    detection-engineering guidance, `core/knowledge`) — advisory reference
    material, never case-specific."""

    model_config = ConfigDict(frozen=True)

    source_type: str
    document_id: str
    title: str
    content: str
    score: float = Field(ge=0.0, le=1.0)
    confidence_label: str
    source: str = "knowledge_layer"
    reason: str


class RetrievalMetrics(BaseModel):
    """Case-level retrieval observability (task requirement: "Retrieval
    metrics, Similarity metrics, Memory hit rate, Latency, Ranking
    statistics, Cache statistics, Context size, Failure metrics"). `cache_*`
    fields are always zero/`False` today — no caching layer sits in front of
    `LongTermMemoryManager`'s retrieval calls (constitution §5: caching is
    reserved for genuinely expensive, idempotent lookups; a semantic
    similarity query against live case data is neither) — kept as explicit
    fields rather than omitted, so a future caching layer has a place to
    report into without a schema change."""

    model_config = ConfigDict(frozen=True)

    categories_queried: int = 0
    total_candidates_considered: int = 0
    total_items_returned: int = 0
    below_threshold_dropped: int = 0
    duplicate_dropped: int = 0
    oversized_context_truncated: int = 0
    vector_latency_ms: float = 0.0
    knowledge_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    min_similarity: float = 0.0
    top_k_per_category: int = 5
    hit: bool = False
    degraded: bool = False
    failed_category_count: int = 0
    query_text_empty: bool = False


class MemoryContext(BaseModel):
    """The Memory Agent's full typed output — blueprint §7's
    `SimilarCaseReferences[]` generalized to every retrieved category
    (ADR-0028)."""

    model_config = ConfigDict(frozen=True)

    query_text: str
    similar_cases: tuple[SimilarCase, ...] = ()
    similar_findings: tuple[SimilarFinding, ...] = ()
    similar_iocs: tuple[SimilarIOC, ...] = ()
    similar_mitre_techniques: tuple[SimilarMitreTechnique, ...] = ()
    similar_reports: tuple[SimilarReport, ...] = ()
    related_knowledge: tuple[RelatedKnowledge, ...] = ()
    metrics: RetrievalMetrics = Field(default_factory=RetrievalMetrics)


class MemoryContextResolutionOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    context: MemoryContext


def _reason(category_label: str, score: float, empty_query: bool) -> str:
    if empty_query:
        return f"Matched against a fallback query signal ({category_label})."
    return (
        f"Retrieved via cross-case semantic similarity search over this case's "
        f"finding/IOC signal ({category_label}, similarity={score:.2f})."
    )


class MemoryContextResolutionTool(
    BaseTool[MemoryContextResolutionInput, MemoryContextResolutionOutput]
):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same already-retrieved input, always returns the same typed
    `MemoryContext`. Applies the oversized-context guard (`MAX_TOTAL_ITEMS`)
    as a final, defense-in-depth truncation — never raises on an
    over-large input."""

    name: ClassVar[str] = "memory_context_resolution"
    description: ClassVar[str] = (
        "Resolves already-retrieved cross-case similarity matches and knowledge "
        "documents into a typed, labeled, case-level MemoryContext."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: MemoryContextResolutionInput) -> MemoryContextResolutionOutput:
        empty_query = not arguments.query_text.strip()

        similar_cases = tuple(
            SimilarCase(
                case_id=item.case_id,
                score=item.score,
                confidence_label=confidence_label(item.score),
                excerpt=item.excerpt,
                recorded_at=item.recorded_at,
                reason=_reason("similar past investigation", item.score, empty_query),
            )
            for item in arguments.similar_cases
        )
        similar_findings = tuple(
            SimilarFinding(
                case_id=item.case_id,
                finding_id=item.record_id,
                score=item.score,
                confidence_label=confidence_label(item.score),
                excerpt=item.excerpt,
                recorded_at=item.recorded_at,
                reason=_reason("similar finding", item.score, empty_query),
            )
            for item in arguments.similar_findings
        )
        similar_iocs = tuple(
            SimilarIOC(
                case_id=item.case_id,
                ioc_record_id=item.record_id,
                score=item.score,
                confidence_label=confidence_label(item.score),
                excerpt=item.excerpt,
                recorded_at=item.recorded_at,
                reason=_reason("related IOC", item.score, empty_query),
            )
            for item in arguments.similar_iocs
        )
        similar_mitre_techniques = tuple(
            SimilarMitreTechnique(
                case_id=item.case_id,
                record_id=item.record_id,
                score=item.score,
                confidence_label=confidence_label(item.score),
                excerpt=item.excerpt,
                recorded_at=item.recorded_at,
                reason=_reason("related MITRE technique", item.score, empty_query),
            )
            for item in arguments.similar_mitre_techniques
        )
        similar_reports = tuple(
            SimilarReport(
                case_id=item.case_id,
                report_id=item.record_id,
                score=item.score,
                confidence_label=confidence_label(item.score),
                excerpt=item.excerpt,
                recorded_at=item.recorded_at,
                reason=_reason("similar report", item.score, empty_query),
            )
            for item in arguments.similar_reports
        )
        related_knowledge = tuple(
            RelatedKnowledge(
                source_type=item.source_type,
                document_id=item.document_id,
                title=item.title,
                content=item.content,
                score=item.score,
                confidence_label=confidence_label(item.score),
                reason=(
                    f"Matched knowledge-base document ({item.source_type}, "
                    f"relevance={item.score:.2f})."
                ),
            )
            for item in arguments.related_knowledge
        )

        (
            similar_cases,
            similar_findings,
            similar_iocs,
            similar_mitre_techniques,
            similar_reports,
            related_knowledge,
            truncated,
        ) = _apply_oversized_context_guard(
            similar_cases,
            similar_findings,
            similar_iocs,
            similar_mitre_techniques,
            similar_reports,
            related_knowledge,
        )

        total_returned = (
            len(similar_cases)
            + len(similar_findings)
            + len(similar_iocs)
            + len(similar_mitre_techniques)
            + len(similar_reports)
            + len(related_knowledge)
        )
        total_candidates = sum(m.raw_candidate_count for m in arguments.category_metrics)
        below_threshold = sum(m.below_threshold_dropped for m in arguments.category_metrics)
        duplicates = sum(m.duplicate_dropped for m in arguments.category_metrics)
        failed_categories = sum(1 for m in arguments.category_metrics if m.degraded)

        metrics = RetrievalMetrics(
            categories_queried=len(arguments.category_metrics),
            total_candidates_considered=total_candidates,
            total_items_returned=total_returned,
            below_threshold_dropped=below_threshold,
            duplicate_dropped=duplicates,
            oversized_context_truncated=truncated,
            vector_latency_ms=arguments.total_latency_ms,
            knowledge_latency_ms=arguments.knowledge_latency_ms,
            total_latency_ms=arguments.total_latency_ms + arguments.knowledge_latency_ms,
            min_similarity=arguments.min_similarity,
            top_k_per_category=arguments.top_k_per_category,
            hit=total_returned > 0,
            degraded=arguments.overall_degraded or empty_query,
            failed_category_count=failed_categories,
            query_text_empty=empty_query,
        )

        context = MemoryContext(
            query_text=arguments.query_text,
            similar_cases=similar_cases,
            similar_findings=similar_findings,
            similar_iocs=similar_iocs,
            similar_mitre_techniques=similar_mitre_techniques,
            similar_reports=similar_reports,
            related_knowledge=related_knowledge,
            metrics=metrics,
        )
        return MemoryContextResolutionOutput(context=context)


def _apply_oversized_context_guard(
    similar_cases: tuple[SimilarCase, ...],
    similar_findings: tuple[SimilarFinding, ...],
    similar_iocs: tuple[SimilarIOC, ...],
    similar_mitre_techniques: tuple[SimilarMitreTechnique, ...],
    similar_reports: tuple[SimilarReport, ...],
    related_knowledge: tuple[RelatedKnowledge, ...],
) -> tuple[
    tuple[SimilarCase, ...],
    tuple[SimilarFinding, ...],
    tuple[SimilarIOC, ...],
    tuple[SimilarMitreTechnique, ...],
    tuple[SimilarReport, ...],
    tuple[RelatedKnowledge, ...],
    int,
]:
    """Caps the combined item count at `MAX_TOTAL_ITEMS`, trimming from the
    end of each category in a fixed, deterministic round-robin order —
    defense-in-depth against a misconfigured retrieval strategy producing an
    oversized context, never expected to trigger under this module's own
    default `MemoryRetrievalConfig` (5 categories x top_k=5 = 25, well under
    the 50-item ceiling)."""
    total = (
        len(similar_cases)
        + len(similar_findings)
        + len(similar_iocs)
        + len(similar_mitre_techniques)
        + len(similar_reports)
        + len(related_knowledge)
    )
    if total <= MAX_TOTAL_ITEMS:
        return (
            similar_cases,
            similar_findings,
            similar_iocs,
            similar_mitre_techniques,
            similar_reports,
            related_knowledge,
            0,
        )

    buckets: list[list[Any]] = [
        list(similar_cases),
        list(similar_findings),
        list(similar_iocs),
        list(similar_mitre_techniques),
        list(similar_reports),
        list(related_knowledge),
    ]
    truncated = 0
    while sum(len(b) for b in buckets) > MAX_TOTAL_ITEMS:
        largest = max(buckets, key=len)
        if not largest:
            break
        largest.pop()
        truncated += 1

    return (
        cast("tuple[SimilarCase, ...]", tuple(buckets[0])),
        cast("tuple[SimilarFinding, ...]", tuple(buckets[1])),
        cast("tuple[SimilarIOC, ...]", tuple(buckets[2])),
        cast("tuple[SimilarMitreTechnique, ...]", tuple(buckets[3])),
        cast("tuple[SimilarReport, ...]", tuple(buckets[4])),
        cast("tuple[RelatedKnowledge, ...]", tuple(buckets[5])),
        truncated,
    )
