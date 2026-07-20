"""Unit tests for core/linux_advisor/hardening_advisor.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.command_analyzer import CommandAnalyzer
from core.linux_advisor.hardening_advisor import BASELINE_RECOMMENDATIONS, HardeningAdvisor
from core.linux_advisor.models import HardeningCategory
from core.linux_advisor.permission_analyzer import PermissionAnalyzer
from core.linux_advisor.permission_parser import parse_ls_permission_string

pytestmark = pytest.mark.unit


def test_baseline_recommendations_always_present_with_no_findings() -> None:
    recs = HardeningAdvisor().advise(command_risks=[], permission_risks=[])
    assert len(recs) == len(BASELINE_RECOMMENDATIONS)
    assert all(r.is_baseline for r in recs)


def test_baseline_covers_all_eight_categories() -> None:
    categories = {r.category for r in BASELINE_RECOMMENDATIONS}
    assert categories == set(HardeningCategory)


def test_chmod_777_triggers_file_permissions_recommendation() -> None:
    command_risk = CommandAnalyzer().analyze("chmod 777 /var/www")
    recs = HardeningAdvisor().advise(command_risks=[command_risk], permission_risks=[])
    triggered = [r for r in recs if not r.is_baseline]
    assert any(r.category == HardeningCategory.FILE_PERMISSIONS for r in triggered)
    assert any(r.related_subject == "/var/www" for r in triggered)


def test_unrestricted_sudo_triggers_sudo_configuration_recommendation() -> None:
    command_risk = CommandAnalyzer().analyze("alice ALL=(ALL) NOPASSWD: ALL")
    recs = HardeningAdvisor().advise(command_risks=[command_risk], permission_risks=[])
    triggered = [r for r in recs if not r.is_baseline]
    assert any(r.category == HardeningCategory.SUDO_CONFIGURATION for r in triggered)


def test_safe_command_triggers_no_finding_based_recommendation() -> None:
    command_risk = CommandAnalyzer().analyze("ls -la /home")
    recs = HardeningAdvisor().advise(command_risks=[command_risk], permission_risks=[])
    triggered = [r for r in recs if not r.is_baseline]
    assert triggered == []


def test_world_writable_permission_triggers_file_permissions_recommendation() -> None:
    analysis = parse_ls_permission_string("-rw-rw-rw-")
    permission_risk = PermissionAnalyzer().analyze(analysis)
    recs = HardeningAdvisor().advise(command_risks=[], permission_risks=[permission_risk])
    triggered = [r for r in recs if not r.is_baseline]
    assert any(r.category == HardeningCategory.FILE_PERMISSIONS for r in triggered)


def test_finding_triggered_and_baseline_are_distinguished() -> None:
    command_risk = CommandAnalyzer().analyze("chown attacker /etc/shadow")
    recs = HardeningAdvisor().advise(command_risks=[command_risk], permission_risks=[])
    triggered = [r for r in recs if not r.is_baseline]
    baseline = [r for r in recs if r.is_baseline]
    assert triggered  # at least one finding-triggered
    assert baseline  # baseline always present too
    assert any(r.category == HardeningCategory.OWNERSHIP for r in triggered)
