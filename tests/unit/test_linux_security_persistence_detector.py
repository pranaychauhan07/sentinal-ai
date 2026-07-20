"""Unit tests for core/linux_security/persistence_detector.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)
from core.linux_security.persistence_detector import detect_persistence_mechanisms

pytestmark = pytest.mark.unit


def _candidate(
    category: LinuxSecurityFindingCategory, subject: str = "web01", **context: object
) -> LinuxSecurityCandidate:
    now = datetime.now(UTC)
    return LinuxSecurityCandidate(
        category=category,
        severity=LinuxSecuritySeverity.HIGH,
        subject=subject,
        title="t",
        first_seen=now,
        last_seen=now,
        context=context,
    )


def test_suspicious_cron_reflagged_as_persistence() -> None:
    cron = [_candidate(LinuxSecurityFindingCategory.SUSPICIOUS_CRON)]
    result = detect_persistence_mechanisms(cron, [], [])
    assert len(result) == 1
    assert result[0].category == LinuxSecurityFindingCategory.PERSISTENCE_MECHANISM
    assert result[0].context["original_category"] == LinuxSecurityFindingCategory.SUSPICIOUS_CRON


def test_suspicious_service_reflagged_as_persistence() -> None:
    service = [_candidate(LinuxSecurityFindingCategory.SUSPICIOUS_SERVICE)]
    result = detect_persistence_mechanisms([], service, [])
    assert len(result) == 1
    assert result[0].category == LinuxSecurityFindingCategory.PERSISTENCE_MECHANISM


def test_new_user_then_escalation_pattern_reflagged() -> None:
    privesc = [
        _candidate(
            LinuxSecurityFindingCategory.PRIVILEGE_ESCALATION,
            pattern="new_user_then_group_escalation",
        )
    ]
    result = detect_persistence_mechanisms([], [], privesc)
    assert len(result) == 1
    assert result[0].category == LinuxSecurityFindingCategory.PERSISTENCE_MECHANISM


def test_bare_new_user_not_treated_as_persistence() -> None:
    privesc = [_candidate(LinuxSecurityFindingCategory.NEW_USER)]
    result = detect_persistence_mechanisms([], [], privesc)
    assert result == []


def test_non_persistence_categories_ignored() -> None:
    root_login = [_candidate(LinuxSecurityFindingCategory.ROOT_LOGIN)]
    assert detect_persistence_mechanisms(root_login, [], []) == []


def test_empty_inputs_return_empty() -> None:
    assert detect_persistence_mechanisms([], [], []) == []
