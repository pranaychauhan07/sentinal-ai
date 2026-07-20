"""Unit tests for core/owasp_web/audit.py."""

from __future__ import annotations

import pytest

from core.owasp_web.audit import AuditAction, log_web_security_audit_event, timed_execution

pytestmark = pytest.mark.unit


def test_log_audit_event_never_raises() -> None:
    log_web_security_audit_event(action=AuditAction.ANALYZED_HEADER, subject="CSP", severity="low")


def test_timed_execution_records_duration() -> None:
    with timed_execution("test_op") as result:
        pass
    assert result["duration_ms"] >= 0.0
