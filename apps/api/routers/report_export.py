"""`/api/v1/cases/{case_id}/reports` routes — the Report Export Framework's
API surface (`docs/adr/0026-report-export-framework.md`), backed by
`core.services.report_export_service`.

All three routes are `GET` (read-only, no side effects, constitution §6) —
rendering a report to a requested format is idempotent given the same
persisted `GeneratedReport`; nothing here mutates case state, so none of
these needed to be the `POST` action-trigger exception `/conversation`
uses.

`_download_response` is this router's "Download Manager" (the task's named
component): it is presentation packaging only (translating an
`ExportedReport` into a Starlette `Response` with the correct media type
and `Content-Disposition` header), never a business decision — the actual
rendering decision already happened in `core.reporting.export_manager.
ExportManager` before this function ever runs, matching constitution §6's
"routers contain no business logic" rule.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query
from fastapi.responses import Response

from apps.api.dependencies import CurrentUserDep, DbSessionDep
from apps.api.schemas import ReportFormatsResponse
from core.reporting.export_manager import ExportedReport
from core.reporting.models import ReportFormat
from core.services.report_export_service import (
    export_report,
    list_supported_formats,
    preview_report,
)

router = APIRouter(prefix="/cases/{case_id}/reports", tags=["reports"])


def _download_response(exported: ExportedReport, *, disposition: str) -> Response:
    return Response(
        content=exported.content,
        media_type=exported.media_type,
        headers={"Content-Disposition": f'{disposition}; filename="{exported.filename}"'},
    )


@router.get(
    "/formats", response_model=ReportFormatsResponse, summary="List supported export formats"
)
async def get_report_formats(
    case_id: uuid.UUID,  # noqa: ARG001 - path param kept for REST symmetry; format list is case-independent
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
) -> ReportFormatsResponse:
    return ReportFormatsResponse(formats=list(list_supported_formats()))


@router.get("/export", summary="Generate and download this case's report in a given format")
async def download_report_export(
    case_id: uuid.UUID,
    session: DbSessionDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
    format: ReportFormat = Query(ReportFormat.PDF),  # noqa: A002 - matches the query param name
    theme: str = Query("light"),
    include_charts: bool = Query(True),
) -> Response:
    exported = await export_report(
        session,
        case_id=case_id,
        export_format=format,
        theme=theme,
        include_charts=include_charts,
    )
    return _download_response(exported, disposition="attachment")


@router.get("/preview", summary="Preview this case's report inline (always HTML)")
async def preview_report_export(
    case_id: uuid.UUID,
    session: DbSessionDep,
    user: CurrentUserDep,  # noqa: ARG001 - readiness placeholder, constitution §6
    theme: str = Query("light"),
) -> Response:
    exported = await preview_report(session, case_id=case_id, theme=theme)
    return _download_response(exported, disposition="inline")
