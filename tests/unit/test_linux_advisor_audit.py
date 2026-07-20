"""Unit tests for core/linux_advisor/audit.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.audit import AuditAction, log_linux_advisor_audit_event, timed_execution

pytestmark = pytest.mark.unit


def test_log_audit_event_never_raises() -> None:
    log_linux_advisor_audit_event(
        action=AuditAction.ANALYZED_COMMAND, subject="chmod", severity="high", detail="test"
    )


def test_log_audit_event_with_minimal_args() -> None:
    log_linux_advisor_audit_event(action=AuditAction.OVERSIZED_INPUT_REJECTED)


def test_timed_execution_records_duration() -> None:
    with timed_execution("test_op") as result:
        pass
    assert result["duration_ms"] >= 0.0


def test_timed_execution_records_duration_even_on_exception() -> None:
    with pytest.raises(ValueError), timed_execution("test_op") as result:
        raise ValueError("boom")
    assert result["duration_ms"] >= 0.0
