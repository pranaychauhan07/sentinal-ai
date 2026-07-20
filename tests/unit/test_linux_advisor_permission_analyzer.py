"""Unit tests for core/linux_advisor/permission_analyzer.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.models import LinuxAdvisorSeverity
from core.linux_advisor.permission_analyzer import PermissionAnalyzer
from core.linux_advisor.permission_parser import parse_ls_line, parse_ls_permission_string

pytestmark = pytest.mark.unit


def test_no_risk_is_explicit_info_not_absence() -> None:
    analysis = parse_ls_permission_string("-rw-r--r--")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.INFO
    assert result.matched_rule_ids == ()
    assert "no permission risk" in result.explanation.lower()


def test_world_writable_flagged() -> None:
    analysis = parse_ls_permission_string("-rw-rw-rw-")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity in (LinuxAdvisorSeverity.MEDIUM, LinuxAdvisorSeverity.HIGH)
    assert "world_writable" in result.matched_rule_ids


def test_world_writable_and_executable_is_high() -> None:
    analysis = parse_ls_permission_string("-rwxrwxrwx")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.HIGH


def test_world_writable_dir_no_sticky_bit_flagged() -> None:
    analysis = parse_ls_permission_string("drwxrwxrwx")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.HIGH
    assert "world_writable_dir_no_sticky_bit" in result.matched_rule_ids


def test_world_writable_dir_with_sticky_bit_not_flagged_for_sticky_rule() -> None:
    analysis = parse_ls_permission_string("drwxrwxrwt")
    result = PermissionAnalyzer().analyze(analysis)
    assert "world_writable_dir_no_sticky_bit" not in result.matched_rule_ids


def test_shadow_world_readable_flagged_critical() -> None:
    analysis = parse_ls_line("-rw-r--r-- 1 root root 1234 Jan 1 00:00 /etc/shadow")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.CRITICAL
    assert "sensitive_file_overly_permissive" in result.matched_rule_ids


def test_shadow_owned_by_non_root_flagged_critical() -> None:
    analysis = parse_ls_line("-rw------- 1 attacker root 1234 Jan 1 00:00 /etc/shadow")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.CRITICAL
    assert "sensitive_file_not_root_owned" in result.matched_rule_ids


def test_shadow_properly_secured_not_flagged() -> None:
    analysis = parse_ls_line("-rw------- 1 root root 1234 Jan 1 00:00 /etc/shadow")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.INFO


def test_suid_on_shell_interpreter_flagged_critical() -> None:
    analysis = parse_ls_line("-rwsr-xr-x 1 root root 1234 Jan 1 00:00 /bin/bash")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.CRITICAL
    assert "suid_sgid_on_shell_interpreter" in result.matched_rule_ids


def test_suid_on_ordinary_binary_flagged_medium() -> None:
    analysis = parse_ls_line("-rwsr-xr-x 1 root root 1234 Jan 1 00:00 /usr/bin/mytool")
    result = PermissionAnalyzer().analyze(analysis)
    assert result.severity == LinuxAdvisorSeverity.MEDIUM
    assert "suid_sgid_set" in result.matched_rule_ids
