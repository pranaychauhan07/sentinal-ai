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
        vulnerability_finding_count=result.vulnerability_finding_count,
        highest_vulnerability_score=result.highest_vulnerability_score,
        linux_security_finding_count=result.linux_security_finding_count,
        highest_linux_security_risk_score=result.highest_linux_security_risk_score,
        linux_advisory_count=result.linux_advisory_count,
        highest_linux_advisory_risk_level=result.highest_linux_advisory_risk_level,
        owasp_web_finding_count=result.owasp_web_finding_count,
        highest_owasp_web_risk_level=result.highest_owasp_web_risk_level,
        sast_finding_count=result.sast_finding_count,
        highest_sast_risk_level=result.highest_sast_risk_level,
        mitre_technique_count=result.mitre_technique_count,
        mitre_distinct_group_count=result.mitre_distinct_group_count,
        incident_response_recommendation_count=result.incident_response_recommendation_count,
        incident_severity=result.incident_severity,
        report_id=result.report_id,
        report_type=result.report_type,
        report_section_count=result.report_section_count,
        report_confidence=result.report_confidence,
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
