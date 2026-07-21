"""`/api/v1/cases/{case_id}/conversation` route — blueprint §13's AI Analyst
Chat, backed by `core.services.conversation_service`. `POST` is this
feature's one sanctioned action-trigger endpoint (constitution §6: "no
verbs in URLs" — modeled as a resource-creation `POST`, identical in kind to
`POST /cases/{case_id}/evidence`): answering a question synchronously runs
the full tool-selection -> retrieval -> context-build -> prompt-build ->
response-orchestration -> citation pipeline
(`core.services.conversation_service.ask_question`). No streaming, no new
auth (existing `get_current_user` placeholder), per this feature's explicit
scope (docs/adr/0025).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from apps.api.dependencies import CurrentUserDep, DbSessionDep, SettingsDep
from apps.api.schemas import (
    ConversationAskRequest,
    ConversationAskResponse,
    SourceReferenceResponse,
)
from core.exceptions import NotFoundError
from core.services import case_service
from core.services.conversation_service import ask_question

router = APIRouter(prefix="/cases/{case_id}/conversation", tags=["conversation"])


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
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})

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
