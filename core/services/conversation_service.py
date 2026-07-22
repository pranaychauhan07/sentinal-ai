"""Conversation Service — the on-demand entry point for blueprint §13's AI
Analyst Chat, backed by `core/conversation`'s deterministic orchestration
pipeline. See `docs/adr/0025-ai-investigation-assistant-conversational-
interface.md` for the full architecture reasoning and
`docs/adr/0029-conversation-persistence-compression-export.md` for the
persistence/compression/export/streaming extension.

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
`core.memory.conversation_repository`/`conversation_db_models` are reached
through `core.memory.conversation_memory`'s existing rule 4j grant — no new
package family, just the two new modules that grant added (ADR-0029).

This module never triggers a new investigation run, never re-scores a
finding, and never persists a new Finding/IOC/Report record — it only reads
what the Case Investigation pipeline already produced (docs/adr/0025
Decision 5) and answers questions grounded in it. It does, per ADR-0029, now
persist the conversation itself (sessions/messages/summaries) — this is
this feature's own data, not a re-derivation of investigation results.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.conversation.compression import (
    build_bounded_history,
    estimate_tokens,
    summarize_turns,
)
from core.conversation.conversation_manager import ConversationManager
from core.conversation.exceptions import EmptyQuestionError
from core.conversation.export import ExportedConversation, ExportedMessage, export_conversation
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
from core.memory.conversation_db_models import ConversationMessageRow
from core.memory.conversation_memory import (
    ConversationMemory,
    DbConversationMemory,
    InMemoryConversationMemory,
)
from core.memory.conversation_repository import (
    ConversationMessageRepository,
    ConversationSessionRepository,
    ConversationSummaryRepository,
)
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
#: future multi-process deployment) inject their own instances instead. Only
#: relevant when `Settings.conversation_persistence_backend == "memory"` —
#: the "database" default constructs a fresh, request-scoped
#: `DbConversationMemory` per call instead (ADR-0029).
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


def _row_to_history_turn(row: ConversationMessageRow) -> ConversationHistoryTurn:
    return ConversationHistoryTurn(role=row.role, content=row.content)


async def _hydrate_bounded_history(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    chat_session_id: uuid.UUID,
    settings: Settings,
    memory: ConversationMemory,
) -> list[ConversationHistoryTurn]:
    """Context Window Management (ADR-0029): assembles the history actually
    sent to `PromptBuilder`, applying compression once a session's persisted
    turn count crosses `Settings.conversation_compression_trigger_turns` and
    always applying `build_bounded_history`'s token budget regardless of
    backend/trigger — so a long session's prompt never grows unbounded."""
    recent_rows = await memory.get_turns(
        case_id, limit=settings.conversation_history_turn_limit, session_id=chat_session_id
    )
    recent_turns = [
        ConversationHistoryTurn(role=turn.role.value, content=turn.content) for turn in recent_rows
    ]

    if settings.conversation_persistence_backend != "database":
        return build_bounded_history(
            summary_text=None,
            recent_turns=recent_turns,
            max_tokens=settings.conversation_max_prompt_history_tokens,
        )

    message_repository = ConversationMessageRepository(session)
    summary_repository = ConversationSummaryRepository(session)
    total = await message_repository.count_by_session(chat_session_id)
    summary_text: str | None = None

    if total > settings.conversation_compression_trigger_turns:
        keep_recent = settings.conversation_summary_keep_recent_turns
        cutoff_index = total - 1 - keep_recent
        existing_summary = await summary_repository.find_by_session(chat_session_id)
        after_index = (
            existing_summary.covers_through_sequence_index if existing_summary is not None else -1
        )
        if cutoff_index > after_index:
            rows_to_summarize = await message_repository.find_by_session(
                chat_session_id,
                limit=total,
                after_sequence_index=after_index,
                up_to_sequence_index=cutoff_index,
            )
            if rows_to_summarize:
                indexed_turns = [
                    (row.sequence_index, _row_to_history_turn(row)) for row in rows_to_summarize
                ]
                result = summarize_turns(indexed_turns)
                combined_summary_text = (
                    f"{existing_summary.summary_text}\n\n{result.summary_text}"
                    if existing_summary is not None
                    else result.summary_text
                )
                combined_count = (
                    existing_summary.summarized_message_count + result.summarized_message_count
                    if existing_summary is not None
                    else result.summarized_message_count
                )
                await summary_repository.upsert(
                    session_id=chat_session_id,
                    case_id=case_id,
                    summary_text=combined_summary_text,
                    covers_through_sequence_index=result.covers_through_sequence_index,
                    summarized_message_count=combined_count,
                )
        refreshed_summary = await summary_repository.find_by_session(chat_session_id)
        summary_text = refreshed_summary.summary_text if refreshed_summary is not None else None

    return build_bounded_history(
        summary_text=summary_text,
        recent_turns=recent_turns,
        max_tokens=settings.conversation_max_prompt_history_tokens,
    )


def _build_conversation_memory(
    session: AsyncSession, *, settings: Settings, injected: ConversationMemory | None
) -> ConversationMemory:
    if injected is not None:
        return injected
    if settings.conversation_persistence_backend == "database":
        return DbConversationMemory(ConversationMessageRepository(session))
    return default_conversation_memory()


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

    memory = _build_conversation_memory(session, settings=settings, injected=conversation_memory)
    sessions = session_manager or default_session_manager()
    manager = conversation_manager or ConversationManager(
        llm_provider=default_chat_model_provider()
    )

    chat_session = sessions.get_or_start(session_id=session_id, case_id=str(case_id))

    if settings.conversation_persistence_backend == "database":
        session_repository = ConversationSessionRepository(session)
        await session_repository.get_or_create(session_id=chat_session.session_id, case_id=case_id)

    guard_result = scan_text(question, settings=settings)

    history = await _hydrate_bounded_history(
        session,
        case_id=case_id,
        chat_session_id=chat_session.session_id,
        settings=settings,
        memory=memory,
    )

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

    await memory.add_turn(
        case_id, ConversationRole.USER, question, session_id=chat_session.session_id
    )
    if settings.conversation_persistence_backend == "database":
        await ConversationMessageRepository(session).append(
            session_id=chat_session.session_id,
            case_id=case_id,
            role=ConversationRole.ASSISTANT.value,
            content=answer.answer_text,
            citations_json=json.dumps([c.model_dump(mode="json") for c in answer.citations]),
            confidence=answer.confidence,
            degraded=answer.degraded,
            selected_categories_json=json.dumps([c.value for c in answer.selected_categories]),
            prompt_injection_flagged=answer.prompt_injection_flagged,
        )
        await ConversationSessionRepository(session).touch(chat_session.session_id)
    else:
        await memory.add_turn(
            case_id,
            ConversationRole.ASSISTANT,
            answer.answer_text,
            session_id=chat_session.session_id,
        )
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


async def stream_answer(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    question: str,
    session_id: uuid.UUID | None,
    settings: Settings,
) -> tuple[ConversationAskResult, AsyncIterator[str]]:
    """Progressive delivery of an already-validated answer (ADR-0029
    Decision 6) — the "streaming" requirement, honestly scoped: the full
    `ask_question` pipeline (retrieval, grounding, citation, validation)
    runs to completion *first* (never partially, never before validation),
    then the validated `answer_text` is chunked word-by-word for the caller
    to forward as it iterates. This is deliberately not raw LLM token
    streaming — see the ADR for why that would conflict with the Response
    Validator's already-shipped guarantee that no ungrounded text ever
    reaches the analyst."""
    result = await ask_question(
        session,
        case_id=case_id,
        question=question,
        session_id=session_id,
        settings=settings,
    )

    async def _chunks() -> AsyncIterator[str]:
        words = result.answer_text.split(" ")
        chunk_size = settings.conversation_stream_chunk_words
        for start in range(0, len(words), chunk_size):
            yield " ".join(words[start : start + chunk_size])

    return result, _chunks()


class ConversationSessionSummary:
    """Plain result carrier for one listed session — mirrors
    `ConversationAskResult`'s "internal, immediately re-shaped" role."""

    __slots__ = ("session_id", "status", "turn_count", "created_at", "last_active_at")

    def __init__(
        self,
        *,
        session_id: uuid.UUID,
        status: str,
        turn_count: int,
        created_at: object,
        last_active_at: object,
    ) -> None:
        self.session_id = session_id
        self.status = status
        self.turn_count = turn_count
        self.created_at = created_at
        self.last_active_at = last_active_at


async def list_conversation_sessions(
    session: AsyncSession, *, case_id: uuid.UUID, settings: Settings
) -> list[ConversationSessionSummary]:
    """Conversation Session listing — the "Conversation Search"/"replay"
    entry point's session picker. Database-backend only: an in-memory-backed
    deployment has no durable session list to show (documented limitation,
    ADR-0029)."""
    if settings.conversation_persistence_backend != "database":
        return []
    rows = await ConversationSessionRepository(session).find_by_case(case_id)
    return [
        ConversationSessionSummary(
            session_id=row.id,
            status=row.status,
            turn_count=row.turn_count,
            created_at=row.created_at,
            last_active_at=row.last_active_at,
        )
        for row in rows
    ]


class ConversationMessageSummary:
    __slots__ = (
        "sequence_index",
        "role",
        "content",
        "created_at",
        "citations",
        "confidence",
        "degraded",
    )

    def __init__(
        self,
        *,
        sequence_index: int,
        role: str,
        content: str,
        created_at: object,
        citations: list[dict[str, object]],
        confidence: float | None,
        degraded: bool,
    ) -> None:
        self.sequence_index = sequence_index
        self.role = role
        self.content = content
        self.created_at = created_at
        self.citations = citations
        self.confidence = confidence
        self.degraded = degraded


def _row_to_message_summary(row: ConversationMessageRow) -> ConversationMessageSummary:
    try:
        citations = json.loads(row.citations_json)
    except (TypeError, ValueError):
        citations = []
    return ConversationMessageSummary(
        sequence_index=row.sequence_index,
        role=row.role,
        content=row.content,
        created_at=row.created_at,
        citations=citations if isinstance(citations, list) else [],
        confidence=row.confidence,
        degraded=row.degraded,
    )


async def get_conversation_history(
    session: AsyncSession, *, case_id: uuid.UUID, session_id: uuid.UUID, settings: Settings
) -> list[ConversationMessageSummary]:
    """Conversation Replay — the full, ordered transcript of one session.
    Database-backend only (ADR-0029)."""
    if settings.conversation_persistence_backend != "database":
        return []
    rows = await ConversationMessageRepository(session).find_by_session(
        session_id, limit=settings.conversation_export_max_messages
    )
    return [_row_to_message_summary(row) for row in rows if row.case_id == case_id]


async def search_conversation_history(
    session: AsyncSession, *, case_id: uuid.UUID, query: str, settings: Settings
) -> list[ConversationMessageSummary]:
    """Conversation Search — deterministic case-insensitive substring search
    over this case's persisted chat content (constitution §5: no
    semantic/embedding search here, matching `RetrievalLayer`'s own
    documented keyword-only scope). Database-backend only."""
    if not query or not query.strip():
        return []
    if settings.conversation_persistence_backend != "database":
        return []
    rows = await ConversationMessageRepository(session).search_by_case(case_id, query=query)
    return [_row_to_message_summary(row) for row in rows]


class ConversationAnalytics:
    """Conversation Analytics — computed on demand from already-persisted
    messages, never a separately-persisted redundant table (constitution
    §14.9: nothing here can't be cheaply recomputed from
    `ConversationMessageRow`)."""

    __slots__ = (
        "total_sessions",
        "total_messages",
        "assistant_message_count",
        "degraded_answer_count",
        "prompt_injection_flag_count",
        "average_confidence",
        "category_usage",
    )

    def __init__(
        self,
        *,
        total_sessions: int,
        total_messages: int,
        assistant_message_count: int,
        degraded_answer_count: int,
        prompt_injection_flag_count: int,
        average_confidence: float,
        category_usage: dict[str, int],
    ) -> None:
        self.total_sessions = total_sessions
        self.total_messages = total_messages
        self.assistant_message_count = assistant_message_count
        self.degraded_answer_count = degraded_answer_count
        self.prompt_injection_flag_count = prompt_injection_flag_count
        self.average_confidence = average_confidence
        self.category_usage = category_usage


async def get_conversation_analytics(
    session: AsyncSession, *, case_id: uuid.UUID, settings: Settings
) -> ConversationAnalytics:
    if settings.conversation_persistence_backend != "database":
        return ConversationAnalytics(
            total_sessions=0,
            total_messages=0,
            assistant_message_count=0,
            degraded_answer_count=0,
            prompt_injection_flag_count=0,
            average_confidence=0.0,
            category_usage={},
        )
    sessions = await ConversationSessionRepository(session).find_by_case(case_id, limit=1_000)
    messages = await ConversationMessageRepository(session).find_by_case(
        case_id, limit=settings.conversation_export_max_messages
    )
    assistant_messages = [m for m in messages if m.role == ConversationRole.ASSISTANT.value]
    confidences = [m.confidence for m in assistant_messages if m.confidence is not None]
    category_usage: dict[str, int] = {}
    for message in assistant_messages:
        try:
            categories = json.loads(message.selected_categories_json)
        except (TypeError, ValueError):
            categories = []
        for category in categories if isinstance(categories, list) else []:
            category_usage[str(category)] = category_usage.get(str(category), 0) + 1

    return ConversationAnalytics(
        total_sessions=len(sessions),
        total_messages=len(messages),
        assistant_message_count=len(assistant_messages),
        degraded_answer_count=sum(1 for m in assistant_messages if m.degraded),
        prompt_injection_flag_count=sum(1 for m in messages if m.prompt_injection_flagged),
        average_confidence=(sum(confidences) / len(confidences)) if confidences else 0.0,
        category_usage=category_usage,
    )


async def export_conversation_transcript(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    session_id: uuid.UUID,
    export_format: str,
    settings: Settings,
) -> ExportedConversation:
    """Conversation Export — renders one session's persisted transcript to
    JSON or Markdown, on demand, persisting nothing new
    (docs/adr/0029-conversation-persistence-compression-export.md
    Decision 5)."""
    rows = await ConversationMessageRepository(session).find_by_session(
        session_id, limit=settings.conversation_export_max_messages
    )
    rows = [row for row in rows if row.case_id == case_id]
    messages: list[ExportedMessage] = []
    for row in rows:
        try:
            citations = json.loads(row.citations_json)
        except (TypeError, ValueError):
            citations = []
        messages.append(
            ExportedMessage(
                sequence_index=row.sequence_index,
                role=row.role,
                content=row.content,
                created_at=row.created_at,
                citations=tuple(citations if isinstance(citations, list) else []),
                confidence=row.confidence,
                degraded=row.degraded,
            )
        )
    return export_conversation(
        format=export_format,
        case_id=str(case_id),
        session_id=str(session_id),
        messages=messages,
    )


__all__ = [
    "ConversationAnalytics",
    "ConversationAskResult",
    "ConversationMessageSummary",
    "ConversationSessionSummary",
    "ask_question",
    "default_conversation_memory",
    "default_session_manager",
    "estimate_tokens",
    "export_conversation_transcript",
    "get_conversation_analytics",
    "get_conversation_history",
    "list_conversation_sessions",
    "search_conversation_history",
    "stream_answer",
]
