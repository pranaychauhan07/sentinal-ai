"""Integration tests for apps/api/exception_handlers.py's remaining
branches (AppError, validation errors, unhandled exceptions) —
context/03_engineering_constitution.md §9.

These attach throwaway diagnostic routes directly onto a test-local app
instance (never onto the real `apps.api.main.app`) purely to trigger each
handled exception type through the real middleware/handler stack, the same
way a genuine domain route eventually will.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import APIRouter
from pydantic import BaseModel
from starlette.testclient import TestClient

from apps.api.main import create_app
from core.config import Settings
from core.exceptions import NotFoundError


class _Payload(BaseModel):
    name: str


@pytest.fixture
def client(test_settings: Settings) -> Iterator[TestClient]:
    app = create_app(test_settings)

    diagnostics = APIRouter()

    @diagnostics.get("/_test/not-found")
    async def _raise_not_found() -> None:
        raise NotFoundError("Widget not found.", details={"widget_id": "123"})

    @diagnostics.get("/_test/unhandled")
    async def _raise_unhandled() -> None:
        raise RuntimeError("boom")

    @diagnostics.post("/_test/validate")
    async def _validate(payload: _Payload) -> dict[str, str]:
        return {"name": payload.name}

    app.include_router(diagnostics)

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.integration
def test_app_error_maps_to_standardized_envelope(client: TestClient) -> None:
    response = client.get("/_test/not-found")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "NOT_FOUND"
    assert body["error"]["message"] == "Widget not found."
    assert body["error"]["details"] == {"widget_id": "123"}
    assert body["request_id"]


@pytest.mark.integration
def test_unhandled_exception_returns_generic_500(client: TestClient) -> None:
    response = client.get("/_test/unhandled")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_SERVER_ERROR"
    # The user-facing message never leaks the internal exception message.
    assert "boom" not in body["error"]["message"]


@pytest.mark.integration
def test_validation_error_returns_422_with_field_errors(client: TestClient) -> None:
    response = client.post("/_test/validate", json={})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["details"]["errors"]


@pytest.mark.integration
def test_valid_request_passes_through_validation(client: TestClient) -> None:
    response = client.post("/_test/validate", json={"name": "widget-1"})
    assert response.status_code == 200
    assert response.json() == {"name": "widget-1"}
