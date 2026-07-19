"""`/api/v1/cases` routes — resource-oriented, plural nouns (constitution §6).
No business logic here: every handler validates/renders and calls exactly
one `core.services.case_service` function (constitution §3).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from apps.api.dependencies import CurrentUserDep, DbSessionDep
from apps.api.schemas import (
    CaseAssignmentUpdateRequest,
    CaseCreateRequest,
    CaseDetailsUpdateRequest,
    CaseLabelsUpdateRequest,
    CaseNoteCreateRequest,
    CaseNoteResponse,
    CaseNoteUpdateRequest,
    CasePriorityUpdateRequest,
    CaseResponse,
    CaseStatusUpdateRequest,
    CaseTagRequest,
    CaseTagResponse,
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
        priority=payload.priority,
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


@router.patch(
    "/{case_id}/details", response_model=CaseResponse, summary="Update a case's title/description"
)
async def update_case_details(
    case_id: uuid.UUID, payload: CaseDetailsUpdateRequest, session: DbSessionDep
) -> CaseResponse:
    case = await case_service.update_case_details(
        session, case_id, title=payload.title, description=payload.description
    )
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.patch(
    "/{case_id}/assignment", response_model=CaseResponse, summary="Update a case's owner/assignee"
)
async def update_case_assignment(
    case_id: uuid.UUID, payload: CaseAssignmentUpdateRequest, session: DbSessionDep
) -> CaseResponse:
    case = await case_service.update_case_assignment(
        session, case_id, owner_id=payload.owner_id, assignee_id=payload.assignee_id
    )
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.patch(
    "/{case_id}/priority", response_model=CaseResponse, summary="Update a case's priority"
)
async def update_case_priority(
    case_id: uuid.UUID, payload: CasePriorityUpdateRequest, session: DbSessionDep
) -> CaseResponse:
    case = await case_service.update_case_priority(session, case_id, payload.priority)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.patch(
    "/{case_id}/labels", response_model=CaseResponse, summary="Replace a case's freeform labels"
)
async def update_case_labels(
    case_id: uuid.UUID, payload: CaseLabelsUpdateRequest, session: DbSessionDep
) -> CaseResponse:
    case = await case_service.update_case_labels(session, case_id, payload.labels)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    return CaseResponse.model_validate(case)


@router.get(
    "/{case_id}/tags",
    response_model=PaginatedResponse[CaseTagResponse],
    summary="List a case's tags",
)
async def list_case_tags(
    case_id: uuid.UUID,
    session: DbSessionDep,
    limit: int = Query(default=200, le=500),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[CaseTagResponse]:
    tags = await case_service.list_case_tags(session, case_id, limit=limit, cursor=cursor)
    items = [CaseTagResponse.model_validate(tag) for tag in tags]
    next_cursor = str(tags[-1].id) if len(tags) == limit else None
    return PaginatedResponse(items=items, next_cursor=next_cursor, limit=limit)


@router.post(
    "/{case_id}/tags",
    response_model=CaseTagResponse,
    status_code=201,
    summary="Attach a tag to a case",
)
async def add_case_tag(
    case_id: uuid.UUID, payload: CaseTagRequest, session: DbSessionDep
) -> CaseTagResponse:
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    tag = await case_service.add_case_tag(session, case_id, payload.tag)
    return CaseTagResponse.model_validate(tag)


@router.delete("/{case_id}/tags/{tag}", status_code=204, summary="Remove a tag from a case")
async def remove_case_tag(case_id: uuid.UUID, tag: str, session: DbSessionDep) -> None:
    removed = await case_service.remove_case_tag(session, case_id, tag)
    if not removed:
        raise NotFoundError(
            f"Tag '{tag}' not found on case {case_id}.",
            details={"case_id": str(case_id), "tag": tag},
        )


@router.get(
    "/{case_id}/notes",
    response_model=PaginatedResponse[CaseNoteResponse],
    summary="List a case's notes",
)
async def list_case_notes(
    case_id: uuid.UUID,
    session: DbSessionDep,
    limit: int = Query(default=200, le=500),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[CaseNoteResponse]:
    notes = await case_service.list_case_notes(session, case_id, limit=limit, cursor=cursor)
    items = [CaseNoteResponse.model_validate(note) for note in notes]
    next_cursor = str(notes[-1].id) if len(notes) == limit else None
    return PaginatedResponse(items=items, next_cursor=next_cursor, limit=limit)


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=201,
    summary="Add an editable note to a case",
)
async def add_case_note(
    case_id: uuid.UUID, payload: CaseNoteCreateRequest, session: DbSessionDep, user: CurrentUserDep
) -> CaseNoteResponse:
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})
    note = await case_service.add_case_note(session, case_id, author_id=user.id, body=payload.body)
    return CaseNoteResponse.model_validate(note)


@router.patch(
    "/{case_id}/notes/{note_id}", response_model=CaseNoteResponse, summary="Edit a case note"
)
async def update_case_note(
    case_id: uuid.UUID,
    note_id: uuid.UUID,
    payload: CaseNoteUpdateRequest,
    session: DbSessionDep,
) -> CaseNoteResponse:
    existing = await case_service.get_case_note(session, note_id)
    if existing is None or existing.case_id != case_id:
        raise NotFoundError(f"Note {note_id} not found.", details={"note_id": str(note_id)})
    note = await case_service.update_case_note(session, note_id, body=payload.body)
    assert note is not None  # existence just confirmed above, within the same session
    return CaseNoteResponse.model_validate(note)


@router.delete("/{case_id}/notes/{note_id}", status_code=204, summary="Delete a case note")
async def delete_case_note(case_id: uuid.UUID, note_id: uuid.UUID, session: DbSessionDep) -> None:
    existing = await case_service.get_case_note(session, note_id)
    if existing is None or existing.case_id != case_id:
        raise NotFoundError(f"Note {note_id} not found.", details={"note_id": str(note_id)})
    await case_service.delete_case_note(session, note_id)
