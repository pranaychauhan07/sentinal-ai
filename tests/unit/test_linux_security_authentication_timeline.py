"""Unit tests for core/linux_security/authentication_timeline.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.authentication_timeline import build_timeline
from core.linux_security.models import LinuxLogEvent

pytestmark = pytest.mark.unit

_BASE = datetime(2026, 7, 18, 2, 14, 0, tzinfo=UTC)


def test_builds_chronologically_sorted_entries() -> None:
    events = [
        LinuxLogEvent(timestamp=_BASE + timedelta(seconds=10), process="auth_success"),
        LinuxLogEvent(timestamp=_BASE, process="auth_failure"),
        LinuxLogEvent(timestamp=_BASE + timedelta(seconds=5), process="sudo"),
    ]
    timeline = build_timeline(events)
    assert [e.event_type for e in timeline] == ["auth_failure", "sudo", "auth_success"]


def test_irrelevant_process_excluded() -> None:
    events = [LinuxLogEvent(timestamp=_BASE, process="CRON")]
    assert build_timeline(events) == []


def test_events_without_timestamp_excluded() -> None:
    events = [LinuxLogEvent(timestamp=None, process="auth_failure")]
    assert build_timeline(events) == []


def test_su_and_disconnect_included() -> None:
    events = [
        LinuxLogEvent(timestamp=_BASE, process="su"),
        LinuxLogEvent(timestamp=_BASE, process="disconnect"),
        LinuxLogEvent(timestamp=_BASE, process="session_opened"),
    ]
    timeline = build_timeline(events)
    assert {e.event_type for e in timeline} == {"su", "disconnect", "session_opened"}


def test_empty_events_returns_empty_timeline() -> None:
    assert build_timeline([]) == []
