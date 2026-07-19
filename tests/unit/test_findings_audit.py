"""Unit tests for core/findings/audit.py."""

from __future__ import annotations

import uuid

import pytest

from core.findings.audit import FindingAuditAction, log_finding_audit_event


@pytest.mark.unit
def test_log_finding_audit_event_never_raises() -> None:
    log_finding_audit_event(
        action=FindingAuditAction.PERSISTED,
        finding_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        technique_id="T1110",
        detail="ok",
    )


@pytest.mark.unit
def test_log_finding_audit_event_handles_none_finding_id() -> None:
    log_finding_audit_event(action=FindingAuditAction.MAPPED, finding_id=None, case_id=uuid.uuid4())
