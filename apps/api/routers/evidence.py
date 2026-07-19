"""`/api/v1/cases/{case_id}/evidence` routes. `POST` is this milestone's one
sanctioned action-trigger endpoint (constitution §6: "no verbs in URLs" —
modeled as a resource-creation `POST`, not a `/analyze` verb sub-resource):
uploading evidence synchronously runs the full ingest -> extract -> generate
-> analyze pipeline (`core.services.case_service.investigate_new_evidence`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Query, UploadFile

from apps.api.dependencies import CurrentUserDep, DbSessionDep, SettingsDep
from apps.api.schemas import EvidenceResponse, EvidenceUploadResponse
from core.exceptions import NotFoundError
from core.schemas import PaginatedResponse
from core.services import case_service
from core.services.evidence_service import list_evidence_for_case

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


@router.post(
    "",
    response_model=EvidenceUploadResponse,
    status_code=201,
    summary="Upload evidence and run the investigation pipeline",
)
async def upload_evidence(
    case_id: uuid.UUID,
    session: DbSessionDep,
    settings: SettingsDep,
    user: CurrentUserDep,
    file: UploadFile = File(...),
) -> EvidenceUploadResponse:
    case = await case_service.get_case(session, case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})

    content = await file.read()
    result = await case_service.investigate_new_evidence(
        session,
        case_id=case_id,
        filename=file.filename or "upload",
        content=content,
        settings=settings,
        ingested_by=user.id,
    )
    return EvidenceUploadResponse(
        case_id=result.case_id,
        evidence_id=result.evidence_id,
        ioc_count=result.ioc_count,
        created_finding_ids=list(result.created_finding_ids),
        merged_finding_ids=list(result.merged_finding_ids),
        soc_risk_score=result.soc_risk_score,
        soc_risk_label=result.soc_risk_label,
        phishing_risk_score=result.phishing_risk_score,
        phishing_risk_label=result.phishing_risk_label,
    )


@router.get(
    "", response_model=PaginatedResponse[EvidenceResponse], summary="List a case's evidence"
)
async def list_case_evidence(
    case_id: uuid.UUID,
    session: DbSessionDep,
    limit: int = Query(default=50, le=200),
    cursor: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[EvidenceResponse]:
    items = await list_evidence_for_case(session, case_id, limit=limit, cursor=cursor)
    responses = [EvidenceResponse.model_validate(item) for item in items]
    next_cursor = str(items[-1].id) if len(items) == limit else None
    return PaginatedResponse(items=responses, next_cursor=next_cursor, limit=limit)
