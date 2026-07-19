"""Unit tests for core/threat_intel/audit.py — log_threat_intel_audit_event."""

from __future__ import annotations

import uuid

import pytest

from core.threat_intel.audit import AuditAction, log_threat_intel_audit_event


@pytest.mark.unit
def test_log_threat_intel_audit_event_does_not_raise() -> None:
    log_threat_intel_audit_event(
        action=AuditAction.PERSISTED,
        ioc_id=uuid.uuid4(),
        evidence_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        ioc_type="ipv4",
        detail="test",
    )


@pytest.mark.unit
def test_log_threat_intel_audit_event_handles_none_ids() -> None:
    log_threat_intel_audit_event(
        action=AuditAction.REJECTED, ioc_id=None, evidence_id=None, case_id=None
    )
