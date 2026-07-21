"""Report Export Service — the on-demand entry point for the Report Export
Framework (blueprint §13's "one-click PDF per module or full-case
executive summary, previewable in-app before download"). See
`docs/adr/0026-report-export-framework.md` for the full architecture
reasoning.

**Rule 4k** (docs/dependency-rules.md): this module may import
`core/reporting` directly — the eleventh documented exception to "services
only call `core/graph`," worded identically to 4a-4j's established shape.
Rendering an already-persisted `GeneratedReport` is deterministic,
no-LLM-reasoning post-processing over data the Report Generator Agent
already produced (via `core/graph`, on the last evidence upload) and
`core/db/report_repository.py` already persisted. Reading
`core.db.{report_repository,case_repository}` needs no new exception at
all: `core/services` -> `core/db` is always sanctioned (constitution §7).

This module never triggers a new investigation run and never regenerates
report *content* — it only reads the case's already-persisted
`GeneratedReport` and renders it to a requested file format.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from core.db.case_repository import CaseRepository
from core.db.report_repository import ReportRepository
from core.exceptions import NotFoundError
from core.reporting.export_manager import ExportedReport, ExportManager
from core.reporting.models import ALL_REPORT_FORMATS, GeneratedReport, ReportFormat
from core.reporting.theme import ReportTheme

_default_export_manager = ExportManager()


def default_export_manager() -> ExportManager:
    return _default_export_manager


def list_supported_formats() -> tuple[ReportFormat, ...]:
    """The task's named "List Report Formats" capability — a pure,
    no-I/O lookup, never requiring a case/report to exist."""
    return ALL_REPORT_FORMATS


async def _load_generated_report(session: AsyncSession, *, case_id: uuid.UUID) -> GeneratedReport:
    case_repository = CaseRepository(session)
    case = await case_repository.get_by_id(case_id)
    if case is None:
        raise NotFoundError(f"Case {case_id} not found.", details={"case_id": str(case_id)})

    report_repository = ReportRepository(session)
    report_row = await report_repository.find_by_case(case_id)
    if report_row is None:
        raise NotFoundError(
            f"Case {case_id} has no generated report yet.",
            details={"case_id": str(case_id)},
        )
    return GeneratedReport.model_validate_json(report_row.report_data_json)


async def export_report(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    export_format: ReportFormat,
    theme: ReportTheme | str | None = None,
    include_charts: bool = True,
    export_manager: ExportManager | None = None,
) -> ExportedReport:
    """Renders this case's already-generated report to `export_format` —
    the task's named "Generate Report" / "Download Report" capability
    (generation and packaging-for-download are the same call here; there is
    no separate on-disk artifact to fetch later, see docs/adr/0026 Decision
    3)."""
    report = await _load_generated_report(session, case_id=case_id)
    manager = export_manager or default_export_manager()
    return manager.export(report, export_format, theme=theme, include_charts=include_charts)


async def preview_report(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    theme: ReportTheme | str | None = None,
    export_manager: ExportManager | None = None,
) -> ExportedReport:
    """The task's named "Preview Report" capability — always renders HTML
    (blueprint §13: "previewable in-app before download"), regardless of
    which format the analyst ultimately intends to download, since PDF/DOCX
    bytes are not directly browser-previewable without a second conversion
    this framework does not add. Charts are always included in a preview
    (an analyst previewing wants to see what they're about to download)."""
    report = await _load_generated_report(session, case_id=case_id)
    manager = export_manager or default_export_manager()
    return manager.export(report, ReportFormat.HTML, theme=theme, include_charts=True)
