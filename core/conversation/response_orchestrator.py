"""`ResponseOrchestrator` — the task's named "Response Orchestrator".

Owns the final stage of the pipeline: call the injected `ChatModelProvider`,
attach citations via `CitationEngine`, and compute the deterministic
confidence/degraded verdict. Kept as its own module (constitution §1.3,
"small, focused modules") rather than folded into `ConversationManager`,
which owns sequencing the *earlier* pipeline stages (tool selection ->
retrieval -> context assembly -> prompt building) but delegates "generate
and score the final answer" to this class.

ADR-0027: a real `ChatModelProvider` can fail (network error, auth
rejection, rate limit) — `orchestrate` catches `ChatProviderError` and
retries with a fresh `TemplateChatModelProvider` for that single request
rather than letting the failure propagate into the conversation pipeline
(constitution §9, "External API failures ... converted to a degraded
result"), recording the fallback so `ConversationManager` can surface it.
"""

from __future__ import annotations

from core.conversation.citation_engine import CitationEngine
from core.conversation.exceptions import ChatProviderError
from core.conversation.llm_provider import ChatModelProvider, TemplateChatModelProvider
from core.conversation.metrics import ConversationMetricsCollector
from core.conversation.models import (
    ChatCompletion,
    PromptPayload,
    ResponseValidationResult,
    RetrievedItem,
    SourceReference,
)
from core.conversation.response_validator import ResponseValidator
from core.logging import get_logger

_logger = get_logger(__name__)

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

    __slots__ = (
        "answer_text",
        "citations",
        "confidence",
        "provider_degraded",
        "used_source_ids",
        "validation",
    )

    def __init__(
        self,
        *,
        answer_text: str,
        citations: tuple[SourceReference, ...],
        confidence: float,
        used_source_ids: tuple[str, ...],
        validation: ResponseValidationResult,
        provider_degraded: bool = False,
    ) -> None:
        self.answer_text = answer_text
        self.citations = citations
        self.confidence = confidence
        self.used_source_ids = used_source_ids
        self.validation = validation
        self.provider_degraded = provider_degraded


class ResponseOrchestrator:
    def __init__(
        self,
        *,
        llm_provider: ChatModelProvider,
        citation_engine: CitationEngine | None = None,
        response_validator: ResponseValidator | None = None,
        metrics: ConversationMetricsCollector | None = None,
    ) -> None:
        self.llm_provider = llm_provider
        self.citation_engine = citation_engine or CitationEngine()
        self.response_validator = response_validator or ResponseValidator()
        self.metrics = metrics

    def _generate(self, prompt: PromptPayload) -> tuple[ChatCompletion, bool]:
        """Returns `(completion, provider_degraded)`. A `ChatProviderError`
        from the configured provider falls back to a fresh
        `TemplateChatModelProvider` for this one request — never crashes the
        pipeline (constitution §9)."""
        try:
            return self.llm_provider.generate(prompt), False
        except ChatProviderError as exc:
            _logger.error("chat_provider_call_failed", error=str(exc))
            if self.metrics is not None:
                self.metrics.record_llm_failure()
            return TemplateChatModelProvider().generate(prompt), True

    def orchestrate(
        self, prompt: PromptPayload, *, available_items: list[RetrievedItem]
    ) -> OrchestratedResponse:
        completion, provider_degraded = self._generate(prompt)
        citations = self.citation_engine.cite(completion, available_items=available_items)
        validation = self.response_validator.validate(
            completion, available_items=available_items, citation_count=len(citations)
        )
        confidence = self._confidence(assembled_item_count=len(available_items))
        if not validation.valid:
            # A failed validation is a "the answer isn't trustworthy" signal,
            # never a crash (constitution §1.7) — degrade confidence to zero
            # so `ConversationManager` can reliably treat it as degraded
            # without re-deriving the same check itself.
            confidence = 0.0
        return OrchestratedResponse(
            answer_text=completion.answer_text,
            citations=citations,
            confidence=confidence,
            used_source_ids=completion.used_source_ids,
            validation=validation,
            provider_degraded=provider_degraded,
        )

    @staticmethod
    def _confidence(*, assembled_item_count: int) -> float:
        """Zero evidence -> zero confidence; otherwise scales with how much
        of the ranked context window was actually filled, capped at 1.0."""
        if assembled_item_count == 0:
            return 0.0
        return min(1.0, _BASE_CONFIDENCE + _CONFIDENCE_PER_ITEM * assembled_item_count)
