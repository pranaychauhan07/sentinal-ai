"""Unit tests for core/exceptions.py."""

from __future__ import annotations

import pytest

from core.exceptions import (
    AgentExecutionError,
    ApprovalRequiredError,
    BusinessRuleError,
    ExternalServiceError,
    InfrastructureError,
    NotFoundError,
    ToolExecutionError,
    ValidationError,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("exc_cls", "expected_code", "expected_status"),
    [
        (ValidationError, "VALIDATION_ERROR", 422),
        (NotFoundError, "NOT_FOUND", 404),
        (BusinessRuleError, "BUSINESS_RULE_VIOLATION", 409),
        (InfrastructureError, "INFRASTRUCTURE_ERROR", 503),
        (ExternalServiceError, "EXTERNAL_SERVICE_ERROR", 502),
        (AgentExecutionError, "AGENT_EXECUTION_ERROR", 500),
        (ToolExecutionError, "TOOL_EXECUTION_ERROR", 500),
        (ApprovalRequiredError, "APPROVAL_REQUIRED", 403),
    ],
)
def test_exception_codes_and_status(
    exc_cls: type[Exception], expected_code: str, expected_status: int
) -> None:
    exc = exc_cls("something went wrong", details={"field": "value"})
    assert exc.code == expected_code  # type: ignore[attr-defined]
    assert exc.http_status == expected_status  # type: ignore[attr-defined]
    assert exc.message == "something went wrong"  # type: ignore[attr-defined]
    assert exc.details == {"field": "value"}  # type: ignore[attr-defined]


@pytest.mark.unit
def test_to_dict_serializes_expected_shape() -> None:
    exc = NotFoundError("Case not found", details={"case_id": "abc-123"})
    assert exc.to_dict() == {
        "code": "NOT_FOUND",
        "message": "Case not found",
        "details": {"case_id": "abc-123"},
    }


@pytest.mark.unit
def test_details_defaults_to_empty_dict() -> None:
    exc = ValidationError("bad input")
    assert exc.details == {}
