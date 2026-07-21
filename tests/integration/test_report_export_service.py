"""Integration test for core/services/report_export_service.py — renders a
case's real, pipeline-generated `GeneratedReport` (via the already-shipped
`ReportGeneratorAgent`) to a concrete file format, mirroring
`tests/integration/test_conversation_service.py`'s "real data, not
hand-built fixtures" pattern.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import plotly.graph_objects as go
import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.db import Base, Database
from core.exceptions import NotFoundError
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.reporting.docx_renderer import DOCXReportRenderer
from core.reporting.export_manager import ExportManager
from core.reporting.models import ReportFormat
from core.reporting.pdf_renderer import PDFReportRenderer
from core.services import case_service, report_export_service

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")


_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class _FakeChartImageEncoder:
    """Avoids the real ~1-2s/chart Kaleido cost in the integration suite
    (constitution §11, "mock at the boundary") — the PDF/DOCX renderer's
    own unit tests already cover real chart-embedding behavior with this
    same fake."""

    def encode(self, figure: go.Figure, *, width: int = 900, height: int = 500) -> bytes:
        return _TINY_PNG


def _fast_export_manager() -> ExportManager:
    encoder = _FakeChartImageEncoder()
    return ExportManager(
        pdf_renderer=PDFReportRenderer(chart_image_encoder=encoder),
        docx_renderer=DOCXReportRenderer(chart_image_encoder=encoder),
    )


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    dataset = load_mitre_dataset(test_settings)
    await import_dataset(db, dataset)
    yield db
    await db.dispose()


async def test_export_report_raises_not_found_for_unknown_case(database: Database) -> None:
    async with database.session_factory() as session:
        with pytest.raises(NotFoundError):
            await report_export_service.export_report(
                session, case_id=uuid.uuid4(), export_format=ReportFormat.HTML
            )


async def test_export_report_raises_not_found_when_no_report_generated_yet(
    database: Database,
) -> None:
    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="No evidence yet", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        with pytest.raises(NotFoundError):
            await report_export_service.export_report(
                session, case_id=case.id, export_format=ReportFormat.HTML
            )


async def test_export_report_html_and_json_against_real_pipeline_output(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Suspicious SSH activity", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    async with database.session_factory() as session:
        html_export = await report_export_service.export_report(
            session, case_id=case.id, export_format=ReportFormat.HTML
        )
    assert html_export.media_type.startswith("text/html")
    assert (
        b"<!doctype html>" in html_export.content.lower()
        or b"<!DOCTYPE html>" in html_export.content
    )

    async with database.session_factory() as session:
        json_export = await report_export_service.export_report(
            session, case_id=case.id, export_format=ReportFormat.JSON
        )
    assert json_export.media_type == "application/json"
    assert str(case.id) in json_export.content.decode("utf-8")

    async with database.session_factory() as session:
        preview = await report_export_service.preview_report(session, case_id=case.id)
    assert preview.format is ReportFormat.HTML
    assert preview.content


async def test_export_report_pdf_and_docx_against_real_pipeline_output(
    database: Database, test_settings: Settings
) -> None:
    content = _SSH_AUTH_LOG.read_bytes()

    async with database.session_factory() as session:
        case = await case_service.create_case(
            session, title="Suspicious SSH activity", analyst_id="local-analyst"
        )
        await session.commit()

    async with database.session_factory() as session:
        await case_service.investigate_new_evidence(
            session,
            case_id=case.id,
            filename="ssh_auth.log",
            content=content,
            settings=test_settings,
            ingested_by="local-analyst",
        )
        await session.commit()

    manager = _fast_export_manager()
    async with database.session_factory() as session:
        pdf_export = await report_export_service.export_report(
            session, case_id=case.id, export_format=ReportFormat.PDF, export_manager=manager
        )
    assert pdf_export.content.startswith(b"%PDF-")

    async with database.session_factory() as session:
        docx_export = await report_export_service.export_report(
            session, case_id=case.id, export_format=ReportFormat.DOCX, export_manager=manager
        )
    assert docx_export.content.startswith(b"PK")  # DOCX is a zip container


def test_list_supported_formats_covers_every_report_format() -> None:
    formats = report_export_service.list_supported_formats()
    assert ReportFormat.PDF in formats
    assert ReportFormat.DOCX in formats
    assert ReportFormat.HTML in formats
