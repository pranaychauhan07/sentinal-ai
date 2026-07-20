"""SSH Authentication Analyzer — brute force, failed-login spikes, root
login, and compromise-after-brute-force detection over `SshAuthParser`'s
already-classified `auth_failure`/`auth_success`/`disconnect`/
`session_opened` events (`core.linux_security.models.LinuxLogEvent.process`).

All thresholds/windows are configurable (task requirement: "no hardcoded
values"), read from `core/config/settings.py` by
`core.services.linux_security_service.LinuxSecurityPipeline`, defaulted here
only for direct/unit-test construction.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)

DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_MINUTES = 10
DEFAULT_FAILED_LOGIN_SPIKE_THRESHOLD = 20
DEFAULT_FAILED_LOGIN_SPIKE_MIN_SOURCES = 3

_AUTH_FAILURE = "auth_failure"
_AUTH_SUCCESS = "auth_success"


def _sliding_window_exceeds(
    timestamps: list[datetime], *, threshold: int, window: timedelta
) -> tuple[bool, int, datetime | None, datetime | None]:
    """Returns `(exceeded, max_count_in_window, window_start, window_end)`
    for a sorted list of timestamps — the shared sliding-window primitive
    every count-based detector in this analyzer reuses (never an unbounded
    global count)."""
    if not timestamps:
        return False, 0, None, None
    ordered = sorted(timestamps)
    best_count = 0
    best_start: datetime | None = None
    best_end: datetime | None = None
    left = 0
    for right in range(len(ordered)):
        while ordered[right] - ordered[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = ordered[left]
            best_end = ordered[right]
    return best_count >= threshold, best_count, best_start, best_end


class SshAuthAnalyzer:
    """Stateless, deterministic. One instance is safe to share across a
    whole pipeline run."""

    def __init__(
        self,
        *,
        brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
        brute_force_window_minutes: int = DEFAULT_BRUTE_FORCE_WINDOW_MINUTES,
        failed_login_spike_threshold: int = DEFAULT_FAILED_LOGIN_SPIKE_THRESHOLD,
        failed_login_spike_min_sources: int = DEFAULT_FAILED_LOGIN_SPIKE_MIN_SOURCES,
    ) -> None:
        self._brute_force_threshold = brute_force_threshold
        self._brute_force_window = timedelta(minutes=brute_force_window_minutes)
        self._spike_threshold = failed_login_spike_threshold
        self._spike_min_sources = failed_login_spike_min_sources

    def analyze(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        candidates: list[LinuxSecurityCandidate] = []

        failures_by_ip: dict[str, list[LinuxLogEvent]] = defaultdict(list)
        successes_by_ip: dict[str, list[LinuxLogEvent]] = defaultdict(list)
        for event in events:
            if event.process == _AUTH_FAILURE and event.ip_address and event.timestamp:
                failures_by_ip[event.ip_address].append(event)
            elif event.process == _AUTH_SUCCESS and event.timestamp:
                if event.ip_address:
                    successes_by_ip[event.ip_address].append(event)
                if event.user == "root":
                    candidates.append(self._root_login_candidate(event))

        brute_force_ips: set[str] = set()
        for ip_address, ip_events in failures_by_ip.items():
            timestamps = [e.timestamp for e in ip_events if e.timestamp is not None]
            exceeded, count, start, end = _sliding_window_exceeds(
                timestamps, threshold=self._brute_force_threshold, window=self._brute_force_window
            )
            if not exceeded:
                continue
            brute_force_ips.add(ip_address)
            line_numbers = tuple(e.line_number for e in ip_events if e.line_number is not None)
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.BRUTE_FORCE,
                    severity=LinuxSecuritySeverity.HIGH,
                    subject=ip_address,
                    subject_type="ip",
                    title=f"SSH brute force from {ip_address}",
                    description=(
                        f"{count} failed login(s) from {ip_address} within "
                        f"{self._brute_force_window}."
                    ),
                    occurrence_count=count,
                    evidence_id=ip_events[0].evidence_id,
                    line_numbers=line_numbers,
                    first_seen=start or ip_events[0].timestamp or datetime.now().astimezone(),
                    last_seen=end or ip_events[-1].timestamp or datetime.now().astimezone(),
                    context={"window_minutes": self._brute_force_window.total_seconds() / 60},
                )
            )

        for ip_address in brute_force_ips:
            success_events = successes_by_ip.get(ip_address)
            if not success_events:
                continue
            latest_success = max(success_events, key=lambda e: e.timestamp or datetime.min)
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.COMPROMISE_AFTER_BRUTE_FORCE,
                    severity=LinuxSecuritySeverity.CRITICAL,
                    subject=ip_address,
                    subject_type="ip",
                    title=f"Successful login from brute-forcing source {ip_address}",
                    description=(
                        f"{ip_address} crossed the brute-force threshold and later "
                        f"authenticated successfully as '{latest_success.user}'."
                    ),
                    evidence_id=latest_success.evidence_id,
                    line_numbers=(
                        (latest_success.line_number,) if latest_success.line_number else ()
                    ),
                    first_seen=latest_success.timestamp or datetime.now().astimezone(),
                    last_seen=latest_success.timestamp or datetime.now().astimezone(),
                    context={"authenticated_user": latest_success.user},
                )
            )

        all_failure_timestamps = [
            e.timestamp
            for ip_events in failures_by_ip.values()
            for e in ip_events
            if e.timestamp is not None
        ]
        distinct_sources = len(failures_by_ip)
        exceeded, count, start, end = _sliding_window_exceeds(
            all_failure_timestamps,
            threshold=self._spike_threshold,
            window=self._brute_force_window,
        )
        if exceeded and distinct_sources >= self._spike_min_sources:
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.FAILED_LOGIN_SPIKE,
                    severity=LinuxSecuritySeverity.MEDIUM,
                    subject="global",
                    subject_type="host",
                    title="Global failed-login spike across many sources",
                    description=(
                        f"{count} failed login(s) across {distinct_sources} distinct "
                        f"source(s) within {self._brute_force_window}."
                    ),
                    occurrence_count=count,
                    first_seen=start or datetime.now().astimezone(),
                    last_seen=end or datetime.now().astimezone(),
                    context={"distinct_sources": distinct_sources},
                )
            )

        return candidates

    def _root_login_candidate(self, event: LinuxLogEvent) -> LinuxSecurityCandidate:
        return LinuxSecurityCandidate(
            category=LinuxSecurityFindingCategory.ROOT_LOGIN,
            severity=LinuxSecuritySeverity.HIGH,
            subject=event.ip_address or event.host or "unknown",
            subject_type="ip" if event.ip_address else "host",
            title="Successful root login",
            description=f"root logged in successfully from {event.ip_address or 'unknown host'}.",
            evidence_id=event.evidence_id,
            line_numbers=(event.line_number,) if event.line_number is not None else (),
            first_seen=event.timestamp or datetime.now().astimezone(),
            last_seen=event.timestamp or datetime.now().astimezone(),
        )
