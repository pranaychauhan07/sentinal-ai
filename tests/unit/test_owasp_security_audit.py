"""Unit tests for core/owasp_security/audit.py."""

from __future__ import annotations

import pytest

from core.owasp_security.audit import AuditAction, log_sast_audit_event, timed_execution

pytestmark = pytest.mark.unit


def test_log_audit_event_never_raises() -> None:
    log_sast_audit_event(
        action=AuditAction.FINDING_DETECTED, subject="sql_injection", severity="high"
    )


def test_timed_execution_records_duration() -> None:
    with timed_execution("test_op") as result:
        pass
    assert result["duration_ms"] >= 0.0
