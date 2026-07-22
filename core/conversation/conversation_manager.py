"""`ConversationManager` — the task's named "Conversation Manager", the
pipeline orchestrator sequencing tool selection -> retrieval -> context
assembly -> prompt building, then delegating final answer generation to
`ResponseOrchestrator` (which owns "call the provider, cite, score").

This is the one place in `core/conversation` that composes the whole
pipeline; every component it calls stays independently testable and
independently swappable (constitution §1.5, "composition over
inheritance"). It never touches `core/memory`/`core/db`/`core/security`
itself — those all happen at the service boundary
(`core/services/conversation_service.py`), per docs/adr/0025 Decision 1/6;
this manager only ever receives already-hydrated, already-screened plain
data.
"""

from __future__ import annotations

from core.conversation.audit import log_conversation_audit_event, timed_execution
from core.conversation.citation_engine import CitationEngine
from core.conversation.context_builder import ConversationContextBuilder
from core.conversation.llm_provider import ChatModelProvider, TemplateChatModelProvider
from core.conversation.metrics import ConversationMetricsCollector
from core.conversation.models import (
    AuditEventAction,
    ConversationAnswer,
    ConversationHistoryTurn,
    ConversationRetrievalContext,
)
from core.conversation.prompt_builder import PromptBuilder
from core.conversation.response_orchestrator import ResponseOrchestrator
from core.conversation.retrieval import RetrievalLayer
from core.conversation.tool_selection import ToolSelectionEngine

#: Below this many total (case-wide) retrievable records, a question is
#: answered but flagged degraded — mirrors every other package's
#: "insufficient evidence, never a forced guess" precedent (constitution
#: §4.7), applied here at the whole-case level rather than per-finding.
MIN_TOTAL_RECORDS_FOR_CONFIDENT_ANSWER = 1


class ConversationManager:
    """Constructed with injected collaborators (constitution §2,
    "Dependency injection") so every stage — including the LLM provider —
    is swappable and independently mockable in tests."""

    def __init__(
        self,
        *,
        tool_selection: ToolSelectionEngine | None = None,
        retrieval: RetrievalLayer | None = None,
        context_builder: ConversationContextBuilder | None = None,
        prompt_builder: PromptBuilder | None = None,
        llm_provider: ChatModelProvider | None = None,
        response_orchestrator: ResponseOrchestrator | None = None,
        metrics: ConversationMetricsCollector | None = None,
    ) -> None:
        self.tool_selection = tool_selection or ToolSelectionEngine()
        self.retrieval = retrieval or RetrievalLayer()
        self.context_builder = context_builder or ConversationContextBuilder()
        self.prompt_builder = prompt_builder or PromptBuilder()
        self.metrics = metrics or ConversationMetricsCollector()
        self.response_orchestrator = response_orchestrator or ResponseOrchestrator(
            llm_provider=llm_provider or TemplateChatModelProvider(),
            citation_engine=CitationEngine(),
            metrics=self.metrics,
        )

    def answer(
        self,
        *,
        case_id: str,
        session_id: str | None,
        question: str,
        retrieval_context: ConversationRetrievalContext,
        history: list[ConversationHistoryTurn] | None = None,
        prompt_injection_flagged: bool = False,
    ) -> ConversationAnswer:
        history = history or []

        log_conversation_audit_event(
            action=AuditEventAction.QUESTION_RECEIVED,
            case_id=case_id,
            session_id=session_id,
            detail=question,
        )
        if prompt_injection_flagged:
            self.metrics.record_prompt_injection_flag()
            log_conversation_audit_event(
                action=AuditEventAction.PROMPT_INJECTION_FLAGGED,
                case_id=case_id,
                session_id=session_id,
                detail=question,
            )

        with timed_execution("conversation_answer") as timing:
            selection = self.tool_selection.select(question)
            log_conversation_audit_event(
                action=AuditEventAction.CATEGORIES_SELECTED,
                case_id=case_id,
                session_id=session_id,
                detail=selection.thought,
                metadata={"categories": [c.value for c in selection.categories]},
            )

            retrieved_items = self.retrieval.retrieve(
                retrieval_context,
                question=question,
                categories=selection.categories,
                allow_fallback=selection.explicit,
            )
            self.metrics.record_retrieval_result(item_count=len(retrieved_items))

            assembled = self.context_builder.assemble(retrieved_items)
            log_conversation_audit_event(
                action=AuditEventAction.CONTEXT_ASSEMBLED,
                case_id=case_id,
                session_id=session_id,
                metadata={
                    "item_count": len(assembled.items),
                    "total_candidates": assembled.total_candidates,
                    "truncated": assembled.truncated,
                },
            )

            prompt = self.prompt_builder.build(
                question=question,
                context=assembled,
                history=history,
                prompt_injection_flagged=prompt_injection_flagged,
            )
            orchestrated = self.response_orchestrator.orchestrate(
                prompt, available_items=list(assembled.items)
            )
            self.metrics.record_llm_call()
            self.metrics.record_citations(len(orchestrated.citations))
            self.metrics.record_duplicate_context_removed(assembled.duplicates_removed)
            if assembled.truncated:
                self.metrics.record_context_truncated(
                    assembled.total_candidates - len(assembled.items)
                )
            if not orchestrated.validation.valid:
                self.metrics.record_validation_failure()
                log_conversation_audit_event(
                    action=AuditEventAction.RESPONSE_VALIDATION_FAILED,
                    case_id=case_id,
                    session_id=session_id,
                    detail="; ".join(orchestrated.validation.issues),
                    metadata={
                        "hallucinated_source_ids": list(
                            orchestrated.validation.hallucinated_source_ids
                        )
                    },
                )

        total_available = (
            len(retrieval_context.findings)
            + len(retrieval_context.iocs)
            + len(retrieval_context.mitre_mappings)
            + len(retrieval_context.reports)
            + len(retrieval_context.timeline_events)
        )
        degraded = (
            len(assembled.items) == 0
            or total_available < MIN_TOTAL_RECORDS_FOR_CONFIDENT_ANSWER
            or not orchestrated.validation.valid
            or orchestrated.provider_degraded
        )
        confidence = 0.0 if degraded and len(assembled.items) == 0 else orchestrated.confidence

        self.metrics.record_question_answered()
        self.metrics.record_processing_time(timing["duration_ms"])
        if degraded:
            self.metrics.record_degraded_answer()
            log_conversation_audit_event(
                action=AuditEventAction.ANSWER_DEGRADED,
                case_id=case_id,
                session_id=session_id,
                detail="No matching case evidence was available to answer this question.",
            )
        else:
            log_conversation_audit_event(
                action=AuditEventAction.ANSWER_GENERATED,
                case_id=case_id,
                session_id=session_id,
                metadata={"citation_count": len(orchestrated.citations), "confidence": confidence},
            )

        return ConversationAnswer(
            answer_text=orchestrated.answer_text,
            citations=orchestrated.citations,
            confidence=confidence,
            degraded=degraded,
            selected_categories=selection.categories,
            prompt_injection_flagged=prompt_injection_flagged,
        )
