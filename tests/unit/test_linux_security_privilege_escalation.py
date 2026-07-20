"""Unit tests for core/linux_security/privilege_escalation.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory
from core.linux_security.privilege_escalation import PrivilegeEscalationDetector

pytestmark = pytest.mark.unit

_BASE = datetime(2026, 7, 18, 10, 0, 0, tzinfo=UTC)


def _event(process: str, message: str, *, seconds: int = 0) -> LinuxLogEvent:
    return LinuxLogEvent(
        timestamp=_BASE + timedelta(seconds=seconds),
        host="web01",
        process=process,
        raw_message=message,
        line_number=seconds + 1,
    )


def test_new_user_creation_detected() -> None:
    candidates = PrivilegeEscalationDetector().analyze(
        [_event("useradd", "new user: name=backdoor, UID=1050, GID=1050")]
    )
    new_user = [c for c in candidates if c.category == LinuxSecurityFindingCategory.NEW_USER]
    assert len(new_user) == 1
    assert new_user[0].subject == "backdoor"


def test_user_deletion_detected() -> None:
    candidates = PrivilegeEscalationDetector().analyze([_event("userdel", "delete user 'olduser'")])
    assert any(c.category == LinuxSecurityFindingCategory.USER_DELETION for c in candidates)


def test_password_change_detected() -> None:
    candidates = PrivilegeEscalationDetector().analyze(
        [_event("passwd", "password changed for deploy")]
    )
    assert any(c.category == LinuxSecurityFindingCategory.PASSWORD_CHANGE for c in candidates)


def test_group_escalation_to_sudo_detected() -> None:
    candidates = PrivilegeEscalationDetector().analyze(
        [_event("usermod", "add 'backdoor' to group 'sudo'")]
    )
    escalations = [
        c for c in candidates if c.category == LinuxSecurityFindingCategory.PRIVILEGE_ESCALATION
    ]
    assert len(escalations) == 1
    assert escalations[0].subject == "backdoor"


def test_group_escalation_to_non_privileged_group_not_flagged() -> None:
    candidates = PrivilegeEscalationDetector().analyze(
        [_event("usermod", "add 'alice' to group 'developers'")]
    )
    assert candidates == []


def test_su_to_root_detected() -> None:
    candidates = PrivilegeEscalationDetector().analyze(
        [_event("su", "session opened for user root by deploy(uid=1001)")]
    )
    assert any(
        c.category == LinuxSecurityFindingCategory.UNAUTHORIZED_ACCOUNT_ACTIVITY for c in candidates
    )


def test_new_user_then_escalation_within_window_is_higher_confidence_combined_finding() -> None:
    events = [
        _event("useradd", "new user: name=backdoor, UID=1050", seconds=0),
        _event("usermod", "add 'backdoor' to group 'sudo'", seconds=60),
    ]
    candidates = PrivilegeEscalationDetector(escalation_chain_window_minutes=15).analyze(events)
    combined = [
        c for c in candidates if c.context.get("pattern") == "new_user_then_group_escalation"
    ]
    assert len(combined) == 1
    assert combined[0].severity.value == "critical"
    assert combined[0].confidence == 0.95


def test_escalation_outside_window_is_not_combined() -> None:
    events = [
        _event("useradd", "new user: name=backdoor, UID=1050", seconds=0),
        _event("usermod", "add 'backdoor' to group 'sudo'", seconds=3600),
    ]
    candidates = PrivilegeEscalationDetector(escalation_chain_window_minutes=15).analyze(events)
    combined = [
        c for c in candidates if c.context.get("pattern") == "new_user_then_group_escalation"
    ]
    assert combined == []


def test_malformed_message_does_not_crash() -> None:
    candidates = PrivilegeEscalationDetector().analyze([_event("useradd", "")])
    assert len(candidates) == 1  # falls back to event.user or "unknown"


def test_empty_events_returns_no_candidates() -> None:
    assert PrivilegeEscalationDetector().analyze([]) == []
