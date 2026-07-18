"""Unit tests for core/schemas.py."""

from __future__ import annotations

import pytest

from core.schemas import (
    DependencyCheck,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    PaginatedResponse,
    ReadinessResponse,
    ServiceStatus,
    VersionResponse,
)


@pytest.mark.unit
def test_error_response_shape() -> None:
    response = ErrorResponse(
        error=ErrorDetail(code="NOT_FOUND", message="missing", details={"id": "1"}),
        request_id="req-1",
    )
    dumped = response.model_dump(mode="json")
    assert dumped == {
        "error": {"code": "NOT_FOUND", "message": "missing", "details": {"id": "1"}},
        "request_id": "req-1",
    }


@pytest.mark.unit
def test_paginated_response_generic_over_any_item_type() -> None:
    page = PaginatedResponse[int](items=[1, 2, 3], next_cursor="3", limit=3)
    assert page.items == [1, 2, 3]
    assert page.next_cursor == "3"


@pytest.mark.unit
def test_health_response_defaults_to_ok() -> None:
    health = HealthResponse()
    assert health.status is ServiceStatus.OK


@pytest.mark.unit
def test_readiness_response_holds_dependency_checks() -> None:
    readiness = ReadinessResponse(
        status=ServiceStatus.DEGRADED,
        checks=[
            DependencyCheck(name="database", status=ServiceStatus.OK),
            DependencyCheck(name="llm_provider", status=ServiceStatus.DEGRADED, detail="no key"),
        ],
    )
    assert readiness.status is ServiceStatus.DEGRADED
    assert len(readiness.checks) == 2


@pytest.mark.unit
def test_version_response_round_trips() -> None:
    version = VersionResponse(name="Cyber Defense Copilot", version="0.1.0", environment="testing")
    assert version.model_dump() == {
        "name": "Cyber Defense Copilot",
        "version": "0.1.0",
        "environment": "testing",
    }
