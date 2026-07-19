"""Integration tests for `/api/v1/cases`, `/evidence`, `/iocs`, `/findings` —
exercises the real FastAPI app via `TestClient` against a real SQLite DB and
the real vendored MITRE bundle, mirroring
tests/integration/test_api_system_endpoints.py's pattern.
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


def test_create_and_get_case(client: TestClient) -> None:
    response = client.post("/api/v1/cases", json={"title": "Phishing report", "severity": "low"})
    assert response.status_code == 201
    body = response.json()
    assert body["title"] == "Phishing report"
    assert body["status"] == "open"
    case_id = body["id"]

    fetched = client.get(f"/api/v1/cases/{case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == case_id


def test_get_nonexistent_case_returns_404_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/cases/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "NOT_FOUND"


def test_list_cases_is_paginated(client: TestClient) -> None:
    client.post("/api/v1/cases", json={"title": "Case A"})
    client.post("/api/v1/cases", json={"title": "Case B"})
    response = client.get("/api/v1/cases", params={"limit": 1})
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["limit"] == 1
    assert body["next_cursor"] is not None


def test_update_case_status(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "To be closed"}).json()
    response = client.patch(f"/api/v1/cases/{created['id']}", json={"status": "closed"})
    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    assert response.json()["closed_at"] is not None


def test_upload_evidence_runs_full_pipeline_and_updates_timeline(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "SSH brute force"}).json()
    case_id = created["id"]

    upload = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("ssh_auth.log", _SSH_AUTH_LOG.read_bytes(), "text/plain")},
    )
    assert upload.status_code == 201
    body = upload.json()
    assert body["case_id"] == case_id
    assert body["ioc_count"] > 0
    assert body["soc_risk_score"] is not None

    case_after = client.get(f"/api/v1/cases/{case_id}").json()
    assert case_after["status"] == "investigating"

    evidence_list = client.get(f"/api/v1/cases/{case_id}/evidence").json()
    assert len(evidence_list["items"]) == 1

    iocs = client.get(f"/api/v1/cases/{case_id}/iocs").json()
    assert len(iocs["items"]) > 0

    timeline = client.get(f"/api/v1/cases/{case_id}/timeline").json()
    event_types = {item["event_type"] for item in timeline["items"]}
    assert "evidence_ingested" in event_types
    assert "agent_analysis" in event_types


def test_upload_evidence_for_missing_case_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence",
        files={"file": ("x.log", b"hello", "text/plain")},
    )
    assert response.status_code == 404
