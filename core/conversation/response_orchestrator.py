"""`ResponseOrchestrator` — the task's named "Response Orchestrator".

Owns the final stage of the pipeline: call the injected `ChatModelProvider`,
attach citations via `CitationEngine`, and compute the deterministic
confidence/degraded verdict. Kept as its own module (constitution §1.3,
"small, focused modules") rather than folded into `ConversationManager`,
which owns sequencing the *earlier* pipeline stages (tool selection ->
retrieval -> context assembly -> prompt building) but delegates "generate
and score the final answer" to this class.
"""

from __future__ import annotations

from core.conversation.citation_engine import CitationEngine
from core.conversation.llm_provider import ChatModelProvider
from core.conversation.models import PromptPayload, RetrievedItem, SourceReference

#: Below this many assembled context items, an answer is scored via the
#: lower branch of `_confidence` — deterministic, never an LLM-guessed
#: number (constitution §1.9).
_BASE_CONFIDENCE = 0.5
_CONFIDENCE_PER_ITEM = 0.1


class OrchestratedResponse:
    """Plain result carrier for `ResponseOrchestrator.orchestrate` — not a
    `BaseModel` since it is purely an internal, same-process return value
    that never crosses a service/API boundary on its own (constitution §2,
    "Dataclasses ... for simple, internal, non-validated data carriers")."""

    __slots__ = ("answer_text", "citations", "confidence", "used_source_ids")

    def __init__(
        self,
        *,
        answer_text: str,
        citations: tuple[SourceReference, ...],
        confidence: float,
        used_source_ids: tuple[str, ...],
    ) -> None:
        self.answer_text = answer_text
        self.citations = citations
        self.confidence = confidence
        self.used_source_ids = used_source_ids


class ResponseOrchestrator:
    def __init__(
        self,
        *,
        llm_provider: ChatModelProvider,
        citation_engine: CitationEngine | None = None,
    ) -> None:
        self.llm_provider = llm_provider
        self.citation_engine = citation_engine or CitationEngine()

    def orchestrate(
        self, prompt: PromptPayload, *, available_items: list[RetrievedItem]
    ) -> OrchestratedResponse:
        completion = self.llm_provider.generate(prompt)
        citations = self.citation_engine.cite(completion, available_items=available_items)
        confidence = self._confidence(assembled_item_count=len(available_items))
        return OrchestratedResponse(
            answer_text=completion.answer_text,
            citations=citations,
            confidence=confidence,
            used_source_ids=completion.used_source_ids,
        )

    @staticmethod
    def _confidence(*, assembled_item_count: int) -> float:
        """Zero evidence -> zero confidence; otherwise scales with how much
        of the ranked context window was actually filled, capped at 1.0."""
        if assembled_item_count == 0:
            return 0.0
        return min(1.0, _BASE_CONFIDENCE + _CONFIDENCE_PER_ITEM * assembled_item_count)
