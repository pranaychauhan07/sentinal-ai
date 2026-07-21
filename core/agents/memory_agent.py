"""Memory Agent — blueprint §7's cross-case learning agent: "have we seen
this IP/pattern before?" (ADR-0028).

Never performs retrieval itself — that already happened, asynchronously, in
`core/services/case_service.py`'s `_hydrate_memory_context_record` (calling
`core.memory.investigation_context.build_investigation_memory_context` plus
a Knowledge Layer search), *before* `engine.run(state)` was ever called. This
agent's own job, exactly mirroring `MitreMappingAgent`'s "resolve, never
recompute" shape: read the already-retrieved raw matches hydrated onto
`CaseInvestigationState.memory_context_record`, and resolve them into a
typed, labeled, case-level `MemoryContext` via
`core.tools.memory_tools.MemoryContextResolutionTool` — never recomputing a
similarity score, a confidence threshold, or a ranking itself. See
ADR-0028 §1 for exactly why retrieval can't happen inside `execute()`
(`BaseAgent.execute()` is synchronous; `LongTermMemoryManager` is async).

Cross-cutting, not evidence-type-gated: `core/services/case_service.py`'s
`_required_capabilities_for` appends `memory_retrieval` to *every* evidence
type's required capabilities, identically to `mitre_technique_mapping`/
`incident_response_synthesis`/`report_generation` (ADR-0028 §4) — retrieval
is meaningful for every case, even one that returns nothing back.

Failure handling (blueprint §7's exact words): "memory retrieval is always
advisory/optional" — a `memory_context_record` of `None` (the vector/
knowledge backends were never reached, or the query signal was empty)
produces a `DEGRADED` result with an empty `MemoryContext`, never a `FAILED`
one; this agent never blocks or fails the rest of the investigation.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from core.agents.base import BaseAgent
from core.agents.confidence import ConfidenceScore
from core.agents.contracts import AgentCapability, AgentExecutionResult, ExecutionStatus
from core.graph.state import CaseInvestigationState
from core.tools.memory_tools import (
    CategoryRetrievalMetricsInput,
    MemoryContext,
    MemoryContextResolutionInput,
    MemoryContextResolutionOutput,
    MemoryContextResolutionTool,
    RawKnowledgeItem,
    RawSimilarItem,
)
from core.tools.registry import ToolRegistry

#: `CaseInvestigationState.memory_context_record`'s per-category keys — kept
#: as a single source of truth so the hydration side (`case_service.py`) and
#: the resolution side (this module) can never drift on the dict shape.
_CATEGORY_STATE_KEYS: tuple[str, ...] = (
    "similar_cases",
    "similar_findings",
    "similar_iocs",
    "similar_mitre_techniques",
    "similar_reports",
)


class MemoryAgentResult(BaseModel):
    """This agent's full output payload — what `AgentExecutionResult.output`
    is built from."""

    model_config = ConfigDict(frozen=True)

    context: MemoryContext | None = None
    skipped_malformed_item_count: int = 0


def default_memory_agent_tool_registry() -> ToolRegistry:
    """`MemoryContextResolutionTool` needs no injected dependency (unlike
    `MitreMappingAgent`'s tool, which needs a loaded `MitreLookup`) — mirrors
    `default_incident_response_agent_tool_registry`'s/
    `default_report_generator_agent_tool_registry`'s identical no-argument
    shape."""
    registry = ToolRegistry()
    registry.register(MemoryContextResolutionTool())
    return registry


def _valid_similar_items(raw_items: object) -> tuple[list[RawSimilarItem], int]:
    """Builds `RawSimilarItem`s from a `memory_context_record` category
    list, skipping (never crashing on) a malformed entry — the same
    "skip, don't crash" pattern `core.agents.mitre_mapping_agent.
    _valid_mapping_records` already established for this exact scenario
    (data hydrated from an external, previously-serialized source)."""
    if not isinstance(raw_items, list):
        return [], 0
    valid: list[RawSimilarItem] = []
    skipped = 0
    for item in raw_items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        try:
            valid.append(RawSimilarItem.model_validate(item))
        except ValueError:
            skipped += 1
    return valid, skipped


def _valid_knowledge_items(raw_items: object) -> tuple[list[RawKnowledgeItem], int]:
    if not isinstance(raw_items, list):
        return [], 0
    valid: list[RawKnowledgeItem] = []
    skipped = 0
    for item in raw_items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        try:
            valid.append(RawKnowledgeItem.model_validate(item))
        except ValueError:
            skipped += 1
    return valid, skipped


def _safe_float(value: object, default: float) -> float:
    """Defensive `float(...)` over an `object`-typed dict value (this
    module's `record` parameter is `dict[str, object]`, since it was
    round-tripped through JSON-safe serialization) — never raises on a
    malformed value, mirroring `core.reporting.charts._safe_int`'s
    identical precedent."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _safe_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _safe_optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _valid_category_metrics(raw_items: object) -> list[CategoryRetrievalMetricsInput]:
    if not isinstance(raw_items, list):
        return []
    valid: list[CategoryRetrievalMetricsInput] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        try:
            valid.append(CategoryRetrievalMetricsInput.model_validate(item))
        except ValueError:
            continue
    return valid


def _build_resolution_input(
    record: dict[str, object],
) -> tuple[MemoryContextResolutionInput, int]:
    """Reduces the hydrated `memory_context_record` dict into the tool's
    typed input, tallying every malformed/skipped item across every
    category (never crashing on one bad entry — constitution §1.7)."""
    skipped_total = 0
    category_items: dict[str, list[RawSimilarItem]] = {}
    for key in _CATEGORY_STATE_KEYS:
        items, skipped = _valid_similar_items(record.get(key))
        category_items[key] = items
        skipped_total += skipped

    knowledge_items, knowledge_skipped = _valid_knowledge_items(record.get("related_knowledge"))
    skipped_total += knowledge_skipped

    category_metrics = _valid_category_metrics(record.get("category_metrics"))

    resolution_input = MemoryContextResolutionInput(
        query_text=str(record.get("query_text", "")),
        similar_cases=category_items["similar_cases"],
        similar_findings=category_items["similar_findings"],
        similar_iocs=category_items["similar_iocs"],
        similar_mitre_techniques=category_items["similar_mitre_techniques"],
        similar_reports=category_items["similar_reports"],
        related_knowledge=knowledge_items,
        category_metrics=category_metrics,
        knowledge_latency_ms=_safe_float(record.get("knowledge_latency_ms"), 0.0),
        knowledge_error=_safe_optional_str(record.get("knowledge_error")),
        total_latency_ms=_safe_float(record.get("total_latency_ms"), 0.0),
        min_similarity=_safe_float(record.get("min_similarity"), 0.0),
        top_k_per_category=_safe_int(record.get("top_k_per_category"), 5),
        overall_degraded=bool(record.get("degraded", False)),
    )
    return resolution_input, skipped_total


class MemoryAgent(BaseAgent):
    """Resolves this case's already-retrieved cross-case similarity matches
    and knowledge documents into a typed, case-level `MemoryContext`. Never
    queries a vector store or the Knowledge Layer itself — those calls
    already happened in `core/services/case_service.py` before this agent
    ever runs (ADR-0028 §1)."""

    name: ClassVar[str] = "memory_agent"
    description: ClassVar[str] = (
        "Surfaces similar past cases, findings, IOCs, MITRE techniques, reports, "
        "and relevant knowledge-base documents retrieved for this case, resolving "
        "them into a typed, labeled MemoryContext."
    )
    responsibilities: ClassVar[tuple[str, ...]] = (
        "Resolve this case's already-retrieved cross-case similarity matches.",
        "Resolve already-retrieved relevant knowledge-base documents.",
        "Never recompute a similarity score, threshold, or ranking itself.",
        "Degrade to an empty MemoryContext rather than failing the investigation.",
    )
    capabilities: ClassVar[tuple[AgentCapability, ...]] = (
        AgentCapability(
            name="memory_retrieval",
            description=(
                "Surfaces cross-case historical context (similar cases, findings, "
                "IOCs, MITRE techniques, reports) and relevant knowledge documents."
            ),
        ),
    )
    tools_used: ClassVar[tuple[str, ...]] = (MemoryContextResolutionTool.name,)

    def execute(self, state: CaseInvestigationState) -> AgentExecutionResult:
        record = state.memory_context_record

        if record is None:
            return AgentExecutionResult(
                agent_name=self.name,
                status=ExecutionStatus.DEGRADED,
                thought=(
                    "No memory context was hydrated for this case (advisory "
                    "retrieval was skipped or unavailable); proceeding with no "
                    "historical context rather than blocking the investigation."
                ),
                confidence=ConfidenceScore.deterministic(),
                output=MemoryAgentResult().model_dump(mode="json"),
            )

        resolution_input, skipped = _build_resolution_input(record)
        result = self.use_tool(MemoryContextResolutionTool.name, resolution_input)
        assert isinstance(result, MemoryContextResolutionOutput)  # noqa: S101 - tool contract

        context = result.context
        state.findings = [*state.findings, context]

        metrics = context.metrics
        if metrics.query_text_empty:
            thought = (
                "No evidence/finding signal was available yet for this case; "
                "memory retrieval was skipped rather than run against an empty query."
            )
            status = ExecutionStatus.DEGRADED
        elif not metrics.hit:
            thought = (
                f"Queried {metrics.categories_queried} memory categor(y/ies) and the "
                "Knowledge Layer; no prior case, finding, IOC, technique, report, or "
                "knowledge document met the similarity/relevance threshold — a clean "
                "bill, not insufficient coverage."
            )
            status = ExecutionStatus.SUCCEEDED
        else:
            thought = (
                f"Surfaced {metrics.total_items_returned} historical/knowledge "
                f"item(s) across {metrics.categories_queried} categor(y/ies) "
                f"({len(context.similar_cases)} similar case(s), "
                f"{len(context.similar_findings)} similar finding(s), "
                f"{len(context.similar_iocs)} similar IOC(s), "
                f"{len(context.similar_mitre_techniques)} similar technique(s), "
                f"{len(context.similar_reports)} similar report(s), "
                f"{len(context.related_knowledge)} knowledge document(s))."
            )
            status = ExecutionStatus.DEGRADED if metrics.degraded else ExecutionStatus.SUCCEEDED
        if skipped:
            thought += f" {skipped} malformed retrieval record(s) were skipped."

        return AgentExecutionResult(
            agent_name=self.name,
            status=status,
            thought=thought,
            confidence=ConfidenceScore.deterministic(),
            output=MemoryAgentResult(
                context=context, skipped_malformed_item_count=skipped
            ).model_dump(mode="json"),
        )
