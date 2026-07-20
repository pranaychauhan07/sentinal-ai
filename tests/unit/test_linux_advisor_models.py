"""Unit tests for core/linux_advisor/models.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.models import (
    LinuxAdvisorSeverity,
    highest_severity,
    severity_rank,
)

pytestmark = pytest.mark.unit


def test_severity_rank_ordering() -> None:
    assert severity_rank(LinuxAdvisorSeverity.INFO) < severity_rank(LinuxAdvisorSeverity.LOW)
    assert severity_rank(LinuxAdvisorSeverity.LOW) < severity_rank(LinuxAdvisorSeverity.MEDIUM)
    assert severity_rank(LinuxAdvisorSeverity.MEDIUM) < severity_rank(LinuxAdvisorSeverity.HIGH)
    assert severity_rank(LinuxAdvisorSeverity.HIGH) < severity_rank(LinuxAdvisorSeverity.CRITICAL)


def test_highest_severity_empty_list_is_info() -> None:
    assert highest_severity([]) == LinuxAdvisorSeverity.INFO


def test_highest_severity_picks_max() -> None:
    severities = [
        LinuxAdvisorSeverity.LOW,
        LinuxAdvisorSeverity.CRITICAL,
        LinuxAdvisorSeverity.MEDIUM,
    ]
    assert highest_severity(severities) == LinuxAdvisorSeverity.CRITICAL
