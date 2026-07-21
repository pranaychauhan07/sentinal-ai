"""Conversation Service — the on-demand entry point for blueprint §13's AI
Analyst Chat, backed by `core/conversation`'s deterministic orchestration
pipeline. See `docs/adr/0025-ai-investigation-assistant-conversational-
interface.md` for the full architecture reasoning.

**Rule 4j** (docs/dependency-rules.md): this module may import
`core/conversation`, `core.memory.conversation_memory`, and
`core.security.prompt_guard` directly — a tenth documented exception to
"services only call `core/graph`," worded identically to 4a-4i's
established shape. Retrieval (hydrating a `ConversationRetrievalContext`
from `Finding`/`IOC`/`Report`/`TimelineEvent` rows) is deterministic,
pre-answer-generation processing with no agent/LLM reasoning involved — the
identical reasoning 4a-4i already applied to evidence ingestion, IOC
extraction, and Finding generation. Reading `core.db.{finding_repository,
ioc_repository,report_repository,timeline_event_repository,case_repository}`
needs no new exception at all: `core/services` -> `core/db` is always
sanctioned (constitution §7), the same reasoning `case_service.py`'s own
docstring already documents for its own repository reads.

This module never triggers a new investigation run, never re-scores a
finding, and never persists a new record — it only reads what the Case
Investigation pipeline already produced (docs/adr/0025 Decision 5) and
answers questions grounded in it.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.conversation.conversation_manager import ConversationManager
from core.conversation.exceptions import EmptyQuestionError
from core.conversation.llm_provider import default_chat_model_provider
from core.conversation.models import (
    ConversationHistoryTurn,
    ConversationRetrievalContext,
    EvidenceCategory,
)
from core.conversation.session_manager import SessionManager
from core.conversation.tool_selection import ToolSelectionEngine
from core.db.case_repository import CaseRepository
from core.db.finding_repository import FindingRepository
from core.db.ioc_repository import IOCRepository
from core.db.report_repository import ReportRepository
from core.db.timeline_event_repository import TimelineEventRepository
from core.exceptions import NotFoundError
from core.knowledge.models import KnowledgeQuery
from core.knowledge.registry import KnowledgeSourceRegistry, default_knowledge_registry
from core.knowledge.retrieval import KeywordKnowledgeRetriever
from core.logging import get_logger
from core.memory.conversation_memory import ConversationMemory, InMemoryConversationMemory
from core.memory.long_term import LongTermMemoryManager
from core.memory.manager import default_long_term_memory
from core.memory.models import ConversationRole
from core.security.prompt_guard import scan_text

_logger = get_logger(__name__)

#: A single, process-wide default conversation memory / session manager
#: pair, mirroring `core.memory.vector_store`'s and
#: `core.agents.registry.default_agent_registry()`'s identical "a documented,
#: explicitly-named singleton is fine; an anonymous module-level cache is
#: not" convention (constitution §2). Callers needing isolation (tests, a
#: future multi-process deployment) inject their own instances instead.
_default_conversation_memory = InMemoryConversationMemory()
_default_session_manager = SessionManager()


def default_conversation_memory() -> InMemoryConversationMemory:
    return _default_conversation_memory


def default_session_manager() -> SessionManager:
    return _default_session_manager


async def _hydrate_knowledge_documents(
    question: str, *, knowledge_registry: KnowledgeSourceRegistry
) -> list[dict[str, object]]:
    """Read-only Knowledge Layer search (ADR-0027) — keyword retrieval over
    whichever sources are registered (see `core.knowledge.bootstrap.
    register_default_knowledge_sources`), advisory: an empty/unregistered
    registry simply yields no results, never an error."""
    retriever = KeywordKnowledgeRetriever(knowledge_registry)
    results = retriever.retrieve(KnowledgeQuery(text=question, limit=10))
    return [
        {
            "document_id": result.document.id,
            "title": result.document.title,
            "content": result.document.content,
            "source_type": result.document.source_type.value,
        }
        for result in results
    ]


async def _hydrate_similar_cases(
    question: str, *, case_id: uuid.UUID, long_term_memory: LongTermMemoryManager
) -> list[dict[str, object]]:
    """Cross-case "similar past investigations" (ADR-0027) — always
    advisory (`LongTermMemoryManager` itself never raises; this is a second,
    belt-and-suspenders layer in case a future backend implementation ever
    does)."""
    try:
        results = await long_term_memory.find_similar_excluding_case(
            question, exclude_case_id=case_id, limit=5
        )
    except Exception as exc:  # noqa: BLE001 - advisory boundary: never blocks the answer
        _logger.error("conversation_similar_case_lookup_failed", error=str(exc))
        return []
    return [
        {
            "case_id": str(result.case_id),
            "finding_id": str(result.finding_id),
            "excerpt": result.excerpt,
            "score": result.score,
            "category": result.category,
        }
        for result in results
    ]


async def _hydrate_retrieval_context(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    question: str,
    settings: Settings,
    knowledge_registry: KnowledgeSourceRegistry | None = None,
    long_term_memory: LongTermMemoryManager | None = None,
) -> ConversationRetrievalContext:
    """Reduces this case's already-persisted Findings/IOCs/Reports/Timeline
    events to plain dicts for `ConversationRetrievalContext` — never
    re-derives a severity/risk/confidence/MITRE mapping (constitution
    §1.9), mirroring `case_service._hydrate_mitre_mapping_records`'s
    identical "read the JSON blob directly" shape.

    ADR-0027: additionally fetches Knowledge Layer / cross-case long-term-
    memory results, but only when `ToolSelectionEngine` actually selects
    those categories for this question — avoids paying for a knowledge
    search or an embedding call on every question that doesn't need one.
    `ConversationManager` re-runs the same, deterministic selection
    internally; this is not a duplicated business decision, just a cheap,
    pure function called twice (constitution §5, "deterministic outputs").
    """
    finding_repository = FindingRepository(session)
    ioc_repository = IOCRepository(session)
    report_repository = ReportRepository(session)
    timeline_repository = TimelineEventRepository(session)

    finding_rows = await finding_repository.find_by_case(
        case_id, limit=settings.finding_max_candidates_per_case
    )
    findings: list[dict[str, object]] = []
    mitre_mappings: list[dict[str, object]] = []
    skipped_record_count = 0
    for row in finding_rows:
        try:
            data = json.loads(row.finding_data_json)
        except (TypeError, ValueError):
            skipped_record_count += 1
            _logger.warning(
                "conversation_hydration_skipped_malformed_finding", finding_id=str(row.id)
            )
            continue
        findings.append(
            {
                "finding_id": str(row.id),
                "title": data.get("title", ""),
                "description": data.get("description", ""),
                "severity": data.get("severity", "info"),
                "risk_score": data.get("risk_score", 0.0),
            }
        )
        for mapping in data.get("mitre_mappings", []):
            if isinstance(mapping, dict) and "technique_id" in mapping:
                mitre_mappings.append(
                    {
                        "finding_id": str(row.id),
                        "technique_id": mapping.get("technique_id"),
                        "tactic_ids": list(mapping.get("tactic_ids", ())),
                        "confidence": mapping.get("confidence", 0.0),
                    }
                )

    ioc_rows = await ioc_repository.find_by_case(
        case_id, limit=settings.finding_max_candidates_per_case
    )
    iocs: list[dict[str, object]] = [
        {
            "ioc_id": str(ioc.id),
            "ioc_type": ioc.ioc_type.value,
            "value": ioc.value,
            "severity": ioc.severity.value,
            "confidence": ioc.confidence,
        }
        for ioc in ioc_rows
    ]

    report_row = await report_repository.find_by_case(case_id)
    reports: list[dict[str, object]] = (
        [
            {
                "report_id": str(report_row.id),
                "title": report_row.title,
                "report_type": report_row.report_type.value,
            }
        ]
        if report_row is not None
        else []
    )

    timeline_rows = await timeline_repository.find_by_case(case_id, limit=200)
    timeline_events: list[dict[str, object]] = [
        {
            "event_id": str(event.id),
            "event_type": event.event_type.value,
            "narrative": event.narrative,
        }
        for event in timeline_rows
    ]

    selection = ToolSelectionEngine().select(question)
    knowledge_documents: list[dict[str, object]] = []
    if EvidenceCategory.KNOWLEDGE in selection.categories:
        knowledge_documents = await _hydrate_knowledge_documents(
            question, knowledge_registry=knowledge_registry or default_knowledge_registry()
        )
    similar_cases: list[dict[str, object]] = []
    if EvidenceCategory.SIMILAR_CASE in selection.categories:
        similar_cases = await _hydrate_similar_cases(
            question,
            case_id=case_id,
            long_term_memory=long_term_memory or default_long_term_memory(),
        )

    return ConversationRetrievalContext(
        case_id=str(case_id),
        findings=tuple(findings),
        iocs=tuple(iocs),
        mitre_mappings=tuple(mitre_mappings),
        reports=tuple(reports),
        timeline_events=tuple(timeline_events),
        knowledge_documents=tuple(knowledge_documents),
        similar_cases=tuple(similar_cases),
        skipped_record_count=skipped_record_count,
    )


class ConversationAskResult:
    """Plain result carrier `apps/api` maps to its response schema — not a
    Pydantic model since it's an internal, same-process return value that
    is immediately re-shaped by the caller (constitution §2, "Dataclasses").
    """

    __slots__ = (
        "session_id",
        "answer_text",
        "citations",
        "confidence",
        "degraded",
        "selected_categories",
        "prompt_injection_flagged",
    )

    def __init__(
        self,
        *,
        session_id: uuid.UUID,
        answer_text: str,
        citations: tuple[object, ...],
        confidence: float,
        degraded: bool,
        selected_categories: tuple[str, ...],
        prompt_injection_flagged: bool,
    ) -> None:
        self.session_id = session_id
        self.answer_text = answer_text
        self.citations = citations
        self.confidence = confidence
        self.degraded = degraded
        self.selected_categories = selected_categories
        self.prompt_injection_flagged = prompt_injection_flagged


async def ask_question(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    question: str,
    session_id: uuid.UUID | None = None,
    settings: Settings,
    conversation_memory: ConversationMemory | None = None,
    session_manager: SessionManager | None = None,
    conversation_manager: ConversationManager | None = None,
    knowledge_registry: KnowledgeSourceRegistry | None = None,
    long_term_memory: LongTermMemoryManager | None = None,
) -> ConversationAskResult:
    """Answers one free-form, case-scoped question — blueprint §13's AI
    Analyst Chat. Never bypasses the deterministic investigation pipeline:
    only reads already-persisted case data (constitution §1.9, docs/adr/0025
    Decision 5); triggers no new analysis."""
    if not question or not question.strip():
        raise EmptyQuestionError("The question must not be empty.")

    case_repository = CaseRepository(session)
    case = await case_repository.get_by_id(case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})

    memory = conversation_memory or default_conversation_memory()
    sessions = session_manager or default_session_manager()
    manager = conversation_manager or ConversationManager(
        llm_provider=default_chat_model_provider()
    )

    chat_session = sessions.get_or_start(session_id=session_id, case_id=str(case_id))

    guard_result = scan_text(question, settings=settings)

    history_turns = await memory.get_turns(case_id, limit=20)
    history = [
        ConversationHistoryTurn(role=turn.role.value, content=turn.content)
        for turn in history_turns
    ]

    retrieval_context = await _hydrate_retrieval_context(
        session,
        case_id=case_id,
        question=question,
        settings=settings,
        knowledge_registry=knowledge_registry,
        long_term_memory=long_term_memory,
    )

    answer = manager.answer(
        case_id=str(case_id),
        session_id=str(chat_session.session_id),
        question=question,
        retrieval_context=retrieval_context,
        history=history,
        prompt_injection_flagged=guard_result.is_flagged,
    )

    await memory.add_turn(case_id, ConversationRole.USER, question)
    await memory.add_turn(case_id, ConversationRole.ASSISTANT, answer.answer_text)
    sessions.record_turn(chat_session.session_id)

    return ConversationAskResult(
        session_id=chat_session.session_id,
        answer_text=answer.answer_text,
        citations=answer.citations,
        confidence=answer.confidence,
        degraded=answer.degraded,
        selected_categories=tuple(c.value for c in answer.selected_categories),
        prompt_injection_flagged=answer.prompt_injection_flagged,
    )
