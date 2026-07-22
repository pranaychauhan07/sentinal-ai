"""`/api/v1/cases/{case_id}/conversation` routes — blueprint §13's AI Analyst
Chat, backed by `core.services.conversation_service`. `POST /conversation`
is this feature's one sanctioned action-trigger endpoint (constitution §6:
"no verbs in URLs" — modeled as a resource-creation `POST`, identical in
kind to `POST /cases/{case_id}/evidence`): answering a question
synchronously runs the full tool-selection -> retrieval -> context-build ->
prompt-build -> response-orchestration -> citation pipeline
(`core.services.conversation_service.ask_question`).

`docs/adr/0029-conversation-persistence-compression-export.md` adds the
remaining routes: session listing/replay/search/analytics (all `GET`,
read-only) and export (`GET`, a download like `/reports/export`) over the
now-persisted conversation data, plus `POST /conversation/stream` —
progressive delivery of an already-validated answer, not raw LLM token
streaming (see that ADR's Decision 6 for why).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Query
from fastapi.responses import Response, StreamingResponse

from apps.api.dependencies import CurrentUserDep, DbSessionDep, SettingsDep
from apps.api.schemas import (
    ConversationAnalyticsResponse,
    ConversationAskRequest,
    ConversationAskResponse,
    ConversationMessageResponse,
    ConversationSessionResponse,
    SourceReferenceResponse,
)
from core.exceptions import NotFoundError
from core.services import case_service
from core.services.conversation_service import (
    ask_question,
    export_conversation_transcript,
    get_conversation_analytics,
    get_conversation_history,
    list_conversation_sessions,
    search_conversation_history,
    stream_answer,
)

router = APIRouter(prefix="/cases/{case_id}/conversation", tags=["conversation"])


async def _require_case(session: DbSessionDep, case_id: uuid.UUID) -> None:
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})


@router.post(
    "",
    response_model=ConversationAskResponse,
    status_code=200,
    summary="Ask a free-form, case-scoped question (AI Analyst Chat)",
)
async def ask(
    case_id: uuid.UUID,
    request: ConversationAskRequest,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> ConversationAskResponse:
    await _require_case(session, case_id)

    result = await ask_question(
        session,
        case_id=case_id,
        question=request.question,
        session_id=request.session_id,
        settings=settings,
    )
    return ConversationAskResponse(
        session_id=result.session_id,
        answer_text=result.answer_text,
        citations=[SourceReferenceResponse.model_validate(c) for c in result.citations],
        confidence=result.confidence,
        degraded=result.degraded,
        selected_categories=list(result.selected_categories),
        prompt_injection_flagged=result.prompt_injection_flagged,
    )


@router.post(
    "/stream",
    summary="Ask a question, receiving the validated answer as progressive text chunks",
)
async def ask_stream(
    case_id: uuid.UUID,
    request: ConversationAskRequest,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> StreamingResponse:
    await _require_case(session, case_id)

    result, chunks = await stream_answer(
        session,
        case_id=case_id,
        question=request.question,
        session_id=request.session_id,
        settings=settings,
    )

    async def _event_stream() -> AsyncIterator[bytes]:
        async for chunk in chunks:
            yield f"event: chunk\ndata: {chunk}\n\n".encode()
        final = ConversationAskResponse(
            session_id=result.session_id,
            answer_text=result.answer_text,
            citations=[SourceReferenceResponse.model_validate(c) for c in result.citations],
            confidence=result.confidence,
            degraded=result.degraded,
            selected_categories=list(result.selected_categories),
            prompt_injection_flagged=result.prompt_injection_flagged,
        )
        yield f"event: done\ndata: {final.model_dump_json()}\n\n".encode()

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@router.get(
    "/sessions",
    response_model=list[ConversationSessionResponse],
    summary="List this case's chat sessions",
)
async def list_sessions(
    case_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> list[ConversationSessionResponse]:
    await _require_case(session, case_id)
    summaries = await list_conversation_sessions(session, case_id=case_id, settings=settings)
    return [
        ConversationSessionResponse(
            session_id=s.session_id,
            status=s.status,
            turn_count=s.turn_count,
            created_at=s.created_at,  # type: ignore[arg-type]
            last_active_at=s.last_active_at,  # type: ignore[arg-type]
        )
        for s in summaries
    ]


@router.get(
    "/sessions/{session_id}/messages",
    response_model=list[ConversationMessageResponse],
    summary="Replay one chat session's full, ordered transcript",
)
async def get_session_messages(
    case_id: uuid.UUID,
    session_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> list[ConversationMessageResponse]:
    await _require_case(session, case_id)
    messages = await get_conversation_history(
        session, case_id=case_id, session_id=session_id, settings=settings
    )
    return [
        ConversationMessageResponse(
            sequence_index=m.sequence_index,
            role=m.role,
            content=m.content,
            created_at=m.created_at,  # type: ignore[arg-type]
            citations=m.citations,
            confidence=m.confidence,
            degraded=m.degraded,
        )
        for m in messages
    ]


@router.get(
    "/sessions/{session_id}/export",
    summary="Export one chat session's transcript as JSON or Markdown",
)
async def export_session(
    case_id: uuid.UUID,
    session_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
    format: str = Query("json"),  # noqa: A002 - matches the query param name
) -> Response:
    await _require_case(session, case_id)
    exported = await export_conversation_transcript(
        session,
        case_id=case_id,
        session_id=session_id,
        export_format=format,
        settings=settings,
    )
    return Response(
        content=exported.content,
        media_type=exported.media_type,
        headers={"Content-Disposition": f'attachment; filename="{exported.filename}"'},
    )


@router.get(
    "/search",
    response_model=list[ConversationMessageResponse],
    summary="Search this case's chat history by keyword",
)
async def search_conversation(
    case_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
    q: str = Query(..., min_length=1, max_length=500),
) -> list[ConversationMessageResponse]:
    await _require_case(session, case_id)
    messages = await search_conversation_history(
        session, case_id=case_id, query=q, settings=settings
    )
    return [
        ConversationMessageResponse(
            sequence_index=m.sequence_index,
            role=m.role,
            content=m.content,
            created_at=m.created_at,  # type: ignore[arg-type]
            citations=m.citations,
            confidence=m.confidence,
            degraded=m.degraded,
        )
        for m in messages
    ]


@router.get(
    "/analytics",
    response_model=ConversationAnalyticsResponse,
    summary="Aggregate usage analytics over this case's chat history",
)
async def conversation_analytics(
    case_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> ConversationAnalyticsResponse:
    await _require_case(session, case_id)
    analytics = await get_conversation_analytics(session, case_id=case_id, settings=settings)
    return ConversationAnalyticsResponse(
        total_sessions=analytics.total_sessions,
        total_messages=analytics.total_messages,
        assistant_message_count=analytics.assistant_message_count,
        degraded_answer_count=analytics.degraded_answer_count,
        prompt_injection_flag_count=analytics.prompt_injection_flag_count,
        average_confidence=analytics.average_confidence,
        category_usage=analytics.category_usage,
    )
