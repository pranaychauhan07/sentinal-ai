"""Unit tests for core/linux_security/service_analyzer.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory
from core.linux_security.service_analyzer import ServiceAnalyzer

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 7, 18, 10, 10, 0, tzinfo=UTC)


def _service_event(message: str, *, process: str = "systemd") -> LinuxLogEvent:
    return LinuxLogEvent(timestamp=_NOW, host="web01", process=process, raw_message=message)


def test_exec_start_referencing_tmp_flagged_high_confidence() -> None:
    candidates = ServiceAnalyzer().analyze(
        [_service_event("Starting evil.service - ExecStart=/tmp/.hidden/evil")]
    )
    assert len(candidates) == 1
    assert candidates[0].category == LinuxSecurityFindingCategory.SUSPICIOUS_SERVICE
    assert candidates[0].confidence == 0.8


def test_started_message_with_nonstandard_path_flagged_low_confidence() -> None:
    candidates = ServiceAnalyzer().analyze(
        [_service_event("Started /opt/custom/evil-agent.service")]
    )
    assert len(candidates) == 1
    assert candidates[0].confidence == 0.4


def test_started_message_with_standard_path_not_flagged() -> None:
    candidates = ServiceAnalyzer().analyze([_service_event("Started /usr/bin/nginx.service")])
    assert candidates == []


def test_started_message_with_bare_service_name_not_flagged() -> None:
    candidates = ServiceAnalyzer().analyze([_service_event("Started nginx.service")])
    assert candidates == []


def test_init_process_also_recognized() -> None:
    candidates = ServiceAnalyzer().analyze([_service_event("ExecStart=/dev/shm/x", process="init")])
    assert len(candidates) == 1


def test_non_service_event_ignored() -> None:
    event = LinuxLogEvent(timestamp=_NOW, process="sudo", raw_message="Started something")
    assert ServiceAnalyzer().analyze([event]) == []


def test_empty_events() -> None:
    assert ServiceAnalyzer().analyze([]) == []
