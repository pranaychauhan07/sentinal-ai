"""Unit tests for core/linux_security/ssh_auth_analyzer.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.models import LinuxLogEvent, LinuxSecurityFindingCategory
from core.linux_security.ssh_auth_analyzer import SshAuthAnalyzer

pytestmark = pytest.mark.unit

_BASE = datetime(2026, 7, 18, 2, 14, 0, tzinfo=UTC)


def _event(
    process: str, *, ip: str | None = "203.0.113.44", user: str | None = None, seconds: int = 0
) -> LinuxLogEvent:
    return LinuxLogEvent(
        timestamp=_BASE + timedelta(seconds=seconds),
        host="web01",
        user=user,
        ip_address=ip,
        process=process,
        raw_message="",
        line_number=seconds + 1,
    )


def test_brute_force_detected_when_threshold_crossed_within_window() -> None:
    events = [_event("auth_failure", seconds=i * 5) for i in range(6)]
    candidates = SshAuthAnalyzer(brute_force_threshold=5).analyze(events)
    brute_force = [c for c in candidates if c.category == LinuxSecurityFindingCategory.BRUTE_FORCE]
    assert len(brute_force) == 1
    assert brute_force[0].subject == "203.0.113.44"
    assert brute_force[0].occurrence_count >= 5


def test_no_brute_force_below_threshold() -> None:
    events = [_event("auth_failure", seconds=i * 5) for i in range(3)]
    candidates = SshAuthAnalyzer(brute_force_threshold=5).analyze(events)
    assert not any(c.category == LinuxSecurityFindingCategory.BRUTE_FORCE for c in candidates)


def test_no_brute_force_when_failures_span_beyond_window() -> None:
    events = [_event("auth_failure", seconds=i * 600) for i in range(6)]  # 10 min apart
    candidates = SshAuthAnalyzer(brute_force_threshold=5, brute_force_window_minutes=10).analyze(
        events
    )
    assert not any(c.category == LinuxSecurityFindingCategory.BRUTE_FORCE for c in candidates)


def test_compromise_after_brute_force_detected() -> None:
    events = [_event("auth_failure", seconds=i * 5) for i in range(6)]
    events.append(_event("auth_success", user="root", seconds=100))
    candidates = SshAuthAnalyzer(brute_force_threshold=5).analyze(events)
    compromise = [
        c
        for c in candidates
        if c.category == LinuxSecurityFindingCategory.COMPROMISE_AFTER_BRUTE_FORCE
    ]
    assert len(compromise) == 1
    assert compromise[0].subject == "203.0.113.44"


def test_root_login_flagged() -> None:
    events = [_event("auth_success", user="root", ip="198.51.100.9")]
    candidates = SshAuthAnalyzer().analyze(events)
    root_logins = [c for c in candidates if c.category == LinuxSecurityFindingCategory.ROOT_LOGIN]
    assert len(root_logins) == 1


def test_non_root_success_not_flagged_as_root_login() -> None:
    events = [_event("auth_success", user="deploy", ip="198.51.100.9")]
    candidates = SshAuthAnalyzer().analyze(events)
    assert not any(c.category == LinuxSecurityFindingCategory.ROOT_LOGIN for c in candidates)


def test_failed_login_spike_across_many_sources() -> None:
    events = []
    for i in range(25):
        events.append(_event("auth_failure", ip=f"10.0.0.{i % 10}", seconds=i))
    candidates = SshAuthAnalyzer(
        failed_login_spike_threshold=20, failed_login_spike_min_sources=3
    ).analyze(events)
    spikes = [
        c for c in candidates if c.category == LinuxSecurityFindingCategory.FAILED_LOGIN_SPIKE
    ]
    assert len(spikes) == 1


def test_no_spike_when_too_few_distinct_sources() -> None:
    events = [_event("auth_failure", ip="203.0.113.44", seconds=i) for i in range(25)]
    candidates = SshAuthAnalyzer(
        failed_login_spike_threshold=20, failed_login_spike_min_sources=3
    ).analyze(events)
    assert not any(
        c.category == LinuxSecurityFindingCategory.FAILED_LOGIN_SPIKE for c in candidates
    )


def test_events_without_timestamp_are_ignored() -> None:
    events = [
        LinuxLogEvent(process="auth_failure", ip_address="1.2.3.4", timestamp=None)
        for _ in range(10)
    ]
    candidates = SshAuthAnalyzer(brute_force_threshold=3).analyze(events)
    assert not any(c.category == LinuxSecurityFindingCategory.BRUTE_FORCE for c in candidates)


def test_empty_events_returns_no_candidates() -> None:
    assert SshAuthAnalyzer().analyze([]) == []
