"""`/api/v1/cases` routes — resource-oriented, plural nouns (constitution §6).
No business logic here: every handler validates/renders and calls exactly
one `core.services.case_service` function (constitution §3).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from apps.api.dependencies import CurrentUserDep, DbSessionDep
from apps.api.schemas import (
    CaseCreateRequest,
    CaseResponse,
    CaseStatusUpdateRequest,
    TimelineEventResponse,
)
from core.db.models.case import CaseStatus
from core.exceptions import NotFoundError
from core.schemas import PaginatedResponse
from core.services import case_service

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseResponse, status_code=201, summary="Create a case")
async def create_case(
    payload: CaseCreateRequest, session: DbSessionDep, user: CurrentUserDep
) -> CaseResponse:
    case = await case_service.create_case(
        session,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        analyst_id=user.id,
    )
    return CaseResponse.model_validate(case)


@router.get("", response_model=PaginatedResponse[CaseResponse], summary="List cases")
async def list_cases(
    session: DbSessionDep,
    status: CaseStatus | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[CaseResponse]:
    cases = await case_service.list_cases(session, status=status, limit=limit, cursor=cursor)
    items = [CaseResponse.model_validate(case) for case in cases]
    next_cursor = str(cases[-1].id) if len(cases) == limit else None
    return PaginatedResponse(items=items, next_cursor=next_cursor, limit=limit)


@router.get("/{case_id}", response_model=CaseResponse, summary="Get a case")
async def get_case(case_id: uuid.UUID, session: DbSessionDep) -> CaseResponse:
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update a case's status")
async def update_case_status(
    case_id: uuid.UUID, payload: CaseStatusUpdateRequest, session: DbSessionDep
) -> CaseResponse:
    case = await case_service.update_case_status(session, case_id, payload.status)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.get(
    "/{case_id}/timeline",
    response_model=PaginatedResponse[TimelineEventResponse],
    summary="List a case's timeline",
)
async def list_timeline(
    case_id: uuid.UUID,
    session: DbSessionDep,
    limit: int = Query(default=200, le=500),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[TimelineEventResponse]:
    events = await case_service.list_timeline_for_case(session, case_id, limit=limit, cursor=cursor)
    items = [TimelineEventResponse.model_validate(event) for event in events]
    next_cursor = str(events[-1].id) if len(events) == limit else None
    return PaginatedResponse(items=items, next_cursor=next_cursor, limit=limit)
