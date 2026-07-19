"""`/api/v1/cases/{case_id}/findings` — read-only: Findings are produced
only as a side effect of `POST /cases/{case_id}/evidence` (`apps/api/
routers/evidence.py`), never created directly through this router."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from apps.api.dependencies import DbSessionDep
from apps.api.schemas import FindingResponse
from core.schemas import PaginatedResponse
from core.services.finding_service import list_findings_for_case

router = APIRouter(prefix="/cases/{case_id}/findings", tags=["findings"])


@router.get("", response_model=PaginatedResponse[FindingResponse], summary="List a case's findings")
async def list_case_findings(
    case_id: uuid.UUID,
    session: DbSessionDep,
    limit: int = Query(default=50, le=200),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[FindingResponse]:
    items = await list_findings_for_case(session, case_id, limit=limit, cursor=cursor)
    responses = [FindingResponse.model_validate(item) for item in items]
    next_cursor = str(items[-1].id) if len(items) == limit else None
    return PaginatedResponse(items=responses, next_cursor=next_cursor, limit=limit)
