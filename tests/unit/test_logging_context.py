"""Unit tests for core/logging/context.py."""

from __future__ import annotations

import pytest
import structlog

from core.logging import (
    bind_agent_name,
    bind_case_id,
    bind_investigation_run_id,
    bind_request_id,
    clear_context,
    logging_context,
    new_id,
)


@pytest.mark.unit
def test_new_id_generates_unique_values() -> None:
    assert new_id() != new_id()


@pytest.mark.unit
def test_bind_request_id_generates_when_absent() -> None:
    request_id = bind_request_id()
    assert request_id
    assert structlog.contextvars.get_contextvars()["request_id"] == request_id


@pytest.mark.unit
def test_bind_request_id_reuses_supplied_value() -> None:
    request_id = bind_request_id("fixed-id")
    assert request_id == "fixed-id"
    assert structlog.contextvars.get_contextvars()["request_id"] == "fixed-id"


@pytest.mark.unit
def test_bind_case_and_agent_and_run_id() -> None:
    bind_case_id("case-1")
    bind_agent_name("soc_analyst_agent")
    run_id = bind_investigation_run_id()

    context = structlog.contextvars.get_contextvars()
    assert context["case_id"] == "case-1"
    assert context["agent_name"] == "soc_analyst_agent"
    assert context["investigation_run_id"] == run_id


@pytest.mark.unit
def test_clear_context_removes_all_bindings() -> None:
    bind_case_id("case-1")
    clear_context()
    assert structlog.contextvars.get_contextvars() == {}


@pytest.mark.unit
def test_logging_context_manager_resets_on_exit() -> None:
    bind_case_id("outer-case")
    with logging_context(agent_name="phishing_agent"):
        context = structlog.contextvars.get_contextvars()
        assert context["agent_name"] == "phishing_agent"
        assert context["case_id"] == "outer-case"

    context_after = structlog.contextvars.get_contextvars()
    assert "agent_name" not in context_after
    assert context_after["case_id"] == "outer-case"
