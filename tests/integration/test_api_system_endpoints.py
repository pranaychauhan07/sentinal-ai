"""Integration tests for the FastAPI foundation: app factory, middleware,
exception handlers, and the /health, /ready, /version endpoints.

Marked ``integration`` because these exercise the full app wiring (lifespan,
database connectivity, middleware, exception handlers) together rather than
any single function in isolation.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from apps.api.main import create_app
from core.config import Settings


@pytest.fixture
def client(test_settings: Settings) -> Iterator[TestClient]:
    app = create_app(test_settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.integration
def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "timestamp" in body


@pytest.mark.integration
def test_ready_endpoint_reports_database_and_llm_checks(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()

    check_names = {check["name"] for check in body["checks"]}
    assert check_names == {"database", "llm_provider"}

    database_check = next(c for c in body["checks"] if c["name"] == "database")
    assert database_check["status"] == "ok"

    # test_settings fixture sets LLM_PROVIDER=ollama, which never requires a key.
    llm_check = next(c for c in body["checks"] if c["name"] == "llm_provider")
    assert llm_check["status"] == "ok"
    assert body["status"] == "ok"


@pytest.mark.integration
def test_version_endpoint_reflects_settings(client: TestClient, test_settings: Settings) -> None:
    response = client.get("/version")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == test_settings.app_name
    assert body["version"] == test_settings.app_version
    assert body["environment"] == "testing"


@pytest.mark.integration
def test_unknown_route_returns_standardized_error_envelope(client: TestClient) -> None:
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "HTTP_ERROR"
    assert "request_id" in body


@pytest.mark.integration
def test_request_id_header_is_echoed_when_supplied(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "my-custom-request-id"})
    assert response.headers["X-Request-ID"] == "my-custom-request-id"


@pytest.mark.integration
def test_request_id_header_is_generated_when_absent(client: TestClient) -> None:
    response = client.get("/health")
    assert "X-Request-ID" in response.headers
    assert len(response.headers["X-Request-ID"]) > 0


@pytest.mark.integration
def test_openapi_schema_is_served(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "Cyber Defense Copilot"
    assert schema["info"]["license"]["name"] == "MIT"
    assert "/health" in schema["paths"]
    assert "/ready" in schema["paths"]
    assert "/version" in schema["paths"]


@pytest.mark.integration
def test_docs_ui_is_served(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
