"""Unit tests for core/tools/linux_tools.py."""

from __future__ import annotations

import pytest

from core.tools.linux_tools import (
    LinuxCommandSummaryInput,
    LinuxHardeningSummaryInput,
    LinuxPermissionSummaryInput,
    LinuxSecurityAdvisoryInput,
    LinuxSecurityAdvisoryTool,
)

pytestmark = pytest.mark.unit


def _command(**overrides: object) -> LinuxCommandSummaryInput:
    defaults: dict[str, object] = {
        "command_name": "chmod",
        "raw_text": "chmod 777 /var/www",
        "severity": "high",
        "confidence": 0.9,
        "explanation": "e",
        "matched_rule_count": 1,
    }
    defaults.update(overrides)
    return LinuxCommandSummaryInput(**defaults)  # type: ignore[arg-type]


def _permission(**overrides: object) -> LinuxPermissionSummaryInput:
    defaults: dict[str, object] = {
        "filename": "/etc/shadow",
        "raw_text": "-rw-r--r--",
        "severity": "critical",
        "confidence": 0.9,
        "explanation": "e",
        "matched_rule_count": 1,
    }
    defaults.update(overrides)
    return LinuxPermissionSummaryInput(**defaults)  # type: ignore[arg-type]


def test_empty_input_returns_zeroed_output() -> None:
    result = LinuxSecurityAdvisoryTool()(LinuxSecurityAdvisoryInput())
    assert result.command_count == 0
    assert result.flagged_command_count == 0
    assert result.severity_counts == {}


def test_counts_flagged_vs_total() -> None:
    commands = [_command(), _command(command_name="ls", matched_rule_count=0)]
    result = LinuxSecurityAdvisoryTool()(LinuxSecurityAdvisoryInput(commands=commands))
    assert result.command_count == 2
    assert result.flagged_command_count == 1


def test_severity_counts_across_commands_and_permissions() -> None:
    commands = [_command(severity="high")]
    permissions = [_permission(severity="critical")]
    result = LinuxSecurityAdvisoryTool()(
        LinuxSecurityAdvisoryInput(commands=commands, permissions=permissions)
    )
    assert result.severity_counts == {"high": 1, "critical": 1}


def test_baseline_vs_finding_triggered_hardening_counts() -> None:
    recs = [
        LinuxHardeningSummaryInput(
            category="file_permissions", recommendation="a", is_baseline=True
        ),
        LinuxHardeningSummaryInput(
            category="sudo_configuration", recommendation="b", is_baseline=False
        ),
    ]
    result = LinuxSecurityAdvisoryTool()(LinuxSecurityAdvisoryInput(hardening_recommendations=recs))
    assert result.hardening_recommendation_count == 2
    assert result.baseline_recommendation_count == 1
    assert result.finding_triggered_recommendation_count == 1


def test_top_findings_ranked_by_severity() -> None:
    commands = [
        _command(command_name="low", severity="low"),
        _command(command_name="critical", severity="critical"),
    ]
    result = LinuxSecurityAdvisoryTool()(LinuxSecurityAdvisoryInput(commands=commands, top_n=1))
    assert len(result.top_command_findings) == 1
    assert result.top_command_findings[0].command_name == "critical"


def test_overall_verdict_passed_through_unchanged() -> None:
    result = LinuxSecurityAdvisoryTool()(
        LinuxSecurityAdvisoryInput(
            overall_risk_level="high", overall_confidence=0.7, overall_explanation="x"
        )
    )
    assert result.overall_risk_level == "high"
    assert result.overall_confidence == 0.7
    assert result.overall_explanation == "x"


def test_deterministic() -> None:
    tool = LinuxSecurityAdvisoryTool()
    arguments = LinuxSecurityAdvisoryInput(commands=[_command()])
    assert tool(arguments) == tool(arguments)
