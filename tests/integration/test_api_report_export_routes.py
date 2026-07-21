"""Integration tests for `/api/v1/cases/{case_id}/reports` — the Report
Export Framework's API surface, exercised via the real FastAPI app +
`TestClient`, mirroring tests/integration/test_api_conversation_routes.py's
pattern.

Only HTML/JSON/formats are exercised through the real API here (fast, no
Kaleido dependency) — PDF/DOCX rendering correctness (including real chart
embedding) is already proven at the renderer-unit-test and
service-integration-test layers with a fake `ChartImageEncoder` injected;
paying the real ~1-2s/chart Kaleido cost a third time, at the slowest test
tier, for the same already-proven behavior would not add coverage
(constitution §11, "mock at the boundary, not the internals" — extended
here to "don't re-pay a real external cost for behavior already verified").
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from scripts.mitre.import_attack_bundle import import_dataset
from starlette.testclient import TestClient

from apps.api.main import create_app
from core.config import Settings
from core.db import Base, Database
from core.knowledge.mitre.bootstrap import load_mitre_dataset

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")


@pytest.fixture
def client(test_settings: Settings) -> Iterator[TestClient]:
    import asyncio

    async def _prepare_schema() -> None:
        db = Database(test_settings)
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        dataset = load_mitre_dataset(test_settings)
        await import_dataset(db, dataset)
        await db.dispose()

    asyncio.run(_prepare_schema())

    app = create_app(test_settings)
    with TestClient(app) as test_client:
        yield test_client


def test_get_report_formats_lists_every_supported_format(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Formats case"}).json()
    response = client.get(f"/api/v1/cases/{created['id']}/reports/formats")
    assert response.status_code == 200
    formats = response.json()["formats"]
    assert set(formats) == {"pdf", "html", "markdown", "json", "docx"}


def test_get_report_formats_for_missing_case_still_returns_the_static_list(
    client: TestClient,
) -> None:
    # The format list is case-independent (list_supported_formats() never
    # looks up a case), so a nonexistent case id still returns 200 — see
    # core/services/report_export_service.py's docstring.
    response = client.get("/api/v1/cases/00000000-0000-0000-0000-000000000000/reports/formats")
    assert response.status_code == 200


def test_export_for_missing_case_returns_404(client: TestClient) -> None:
    response = client.get(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/reports/export?format=html"
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_export_for_case_with_no_report_yet_returns_404(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "No report yet"}).json()
    response = client.get(f"/api/v1/cases/{created['id']}/reports/export?format=html")
    assert response.status_code == 404


def test_export_html_and_json_against_real_pipeline_output(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "SSH brute force report"}).json()
    case_id = created["id"]

    upload = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("ssh_auth.log", _SSH_AUTH_LOG.read_bytes(), "text/plain")},
    )
    assert upload.status_code == 201

    html_response = client.get(f"/api/v1/cases/{case_id}/reports/export?format=html")
    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "attachment" in html_response.headers["content-disposition"]
    assert b"<!doctype html>" in html_response.content.lower()

    json_response = client.get(f"/api/v1/cases/{case_id}/reports/export?format=json")
    assert json_response.status_code == 200
    assert json_response.headers["content-type"] == "application/json"
    assert case_id in json_response.text

    preview_response = client.get(f"/api/v1/cases/{case_id}/reports/preview")
    assert preview_response.status_code == 200
    assert "inline" in preview_response.headers["content-disposition"]
    assert b"<!doctype html>" in preview_response.content.lower()


def test_export_respects_dark_theme_query_param(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Dark theme report"}).json()
    case_id = created["id"]
    client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("ssh_auth.log", _SSH_AUTH_LOG.read_bytes(), "text/plain")},
    )

    response = client.get(f"/api/v1/cases/{case_id}/reports/export?format=html&theme=dark")
    assert response.status_code == 200
    assert b'data-theme="dark"' in response.content
