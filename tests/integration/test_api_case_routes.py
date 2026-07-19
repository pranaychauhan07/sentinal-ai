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


def test_create_case_defaults_to_medium_priority(client: TestClient) -> None:
    response = client.post("/api/v1/cases", json={"title": "Priority default"})
    body = response.json()
    assert body["priority"] == "medium"
    assert body["risk_score"] is None
    # `owner_id` defaults to the creating analyst (ADR-0015 point 4);
    # `assignee_id` has no default until explicitly assigned.
    assert body["owner_id"] == "local-analyst"
    assert body["assignee_id"] is None


def test_create_case_rejects_exact_duplicate(client: TestClient) -> None:
    client.post("/api/v1/cases", json={"title": "Dup case"})
    response = client.post("/api/v1/cases", json={"title": "Dup case"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "BUSINESS_RULE_VIOLATION"


def test_update_case_status_rejects_illegal_transition(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Illegal jump"}).json()
    response = client.patch(f"/api/v1/cases/{created['id']}", json={"status": "archived"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "BUSINESS_RULE_VIOLATION"

    unchanged = client.get(f"/api/v1/cases/{created['id']}").json()
    assert unchanged["status"] == "open"


def test_update_case_status_still_allows_legal_transition(client: TestClient) -> None:
    """Regression: the still-legal transition path this endpoint already
    supported before ADR-0015's validation was added must keep working."""
    created = client.post("/api/v1/cases", json={"title": "Still works"}).json()
    response = client.patch(f"/api/v1/cases/{created['id']}", json={"status": "investigating"})
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


def test_update_case_details(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Original"}).json()
    response = client.patch(
        f"/api/v1/cases/{created['id']}/details",
        json={"title": "Renamed", "description": "new description"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["title"] == "Renamed"
    assert body["description"] == "new description"


def test_update_case_assignment(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Assign me"}).json()
    response = client.patch(
        f"/api/v1/cases/{created['id']}/assignment",
        json={"owner_id": "owner-1", "assignee_id": "assignee-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["owner_id"] == "owner-1"
    assert body["assignee_id"] == "assignee-1"


def test_update_case_priority(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Priority me"}).json()
    response = client.patch(
        f"/api/v1/cases/{created['id']}/priority", json={"priority": "critical"}
    )
    assert response.status_code == 200
    assert response.json()["priority"] == "critical"


def test_update_case_labels(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Labels me"}).json()
    response = client.patch(
        f"/api/v1/cases/{created['id']}/labels", json={"labels": {"env": "prod"}}
    )
    assert response.status_code == 200


def test_case_tag_crud(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Tag me"}).json()
    case_id = created["id"]

    add_response = client.post(f"/api/v1/cases/{case_id}/tags", json={"tag": "phishing"})
    assert add_response.status_code == 201
    assert add_response.json()["tag"] == "phishing"

    list_response = client.get(f"/api/v1/cases/{case_id}/tags")
    assert [t["tag"] for t in list_response.json()["items"]] == ["phishing"]

    remove_response = client.delete(f"/api/v1/cases/{case_id}/tags/phishing")
    assert remove_response.status_code == 204

    empty_list = client.get(f"/api/v1/cases/{case_id}/tags")
    assert empty_list.json()["items"] == []


def test_remove_nonexistent_tag_returns_404(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "No tag"}).json()
    response = client.delete(f"/api/v1/cases/{created['id']}/tags/missing")
    assert response.status_code == 404


def test_case_note_crud(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"title": "Note me"}).json()
    case_id = created["id"]

    add_response = client.post(f"/api/v1/cases/{case_id}/notes", json={"body": "first note"})
    assert add_response.status_code == 201
    note_id = add_response.json()["id"]
    assert add_response.json()["author_id"] == "local-analyst"

    update_response = client.patch(
        f"/api/v1/cases/{case_id}/notes/{note_id}", json={"body": "edited note"}
    )
    assert update_response.status_code == 200
    assert update_response.json()["body"] == "edited note"

    list_response = client.get(f"/api/v1/cases/{case_id}/notes")
    assert len(list_response.json()["items"]) == 1

    delete_response = client.delete(f"/api/v1/cases/{case_id}/notes/{note_id}")
    assert delete_response.status_code == 204

    empty_list = client.get(f"/api/v1/cases/{case_id}/notes")
    assert empty_list.json()["items"] == []

    timeline = client.get(f"/api/v1/cases/{case_id}/timeline").json()
    manual_notes = [e for e in timeline["items"] if e["event_type"] == "manual_note"]
    assert len(manual_notes) == 3


def test_update_note_for_wrong_case_returns_404(client: TestClient) -> None:
    case_one = client.post("/api/v1/cases", json={"title": "Case One"}).json()
    case_two = client.post("/api/v1/cases", json={"title": "Case Two"}).json()
    note = client.post(
        f"/api/v1/cases/{case_one['id']}/notes", json={"body": "belongs to one"}
    ).json()

    response = client.patch(
        f"/api/v1/cases/{case_two['id']}/notes/{note['id']}", json={"body": "hijack attempt"}
    )
    assert response.status_code == 404

    # The note's body must be unchanged — the 404 must be raised before any
    # mutation, not after (a real correctness hazard if checked post-write).
    unchanged = client.get(f"/api/v1/cases/{case_one['id']}/notes").json()
    assert unchanged["items"][0]["body"] == "belongs to one"
