"""Unit tests for core/reporting/audit.py's export-stage addition
(`log_report_export_audit_event`) — the generation-stage function
(`log_report_generation_audit_event`) is exercised indirectly throughout
`test_reporting_report_engine.py` and stays untested here directly to avoid
duplicating that coverage.
"""

from __future__ import annotations

import pytest

from core.reporting.audit import AuditAction, log_report_export_audit_event

pytestmark = pytest.mark.unit


def test_log_report_export_audit_event_returns_none_and_never_raises() -> None:
    # Structured-logging emission has no return contract to assert on
    # beyond "never raises" (constitution §9's degraded-not-fatal rule for
    # audit logging) — this call succeeding is the assertion.
    log_report_export_audit_event(
        action=AuditAction.EXPORT_GENERATED, case_id="case-1", detail="format=pdf"
    )


def test_export_audit_actions_are_distinct_from_generation_actions() -> None:
    assert AuditAction.EXPORT_GENERATED != AuditAction.REPORT_GENERATED
    assert AuditAction.EXPORT_FAILED.value == "export_failed"
    assert AuditAction.OVERSIZED_EXPORT_REJECTED.value == "oversized_export_rejected"
