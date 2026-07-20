"""Authentication Timeline — builds a chronologically sorted
`list[AuthenticationTimelineEntry]` from SSH auth events, sudo events, and
su/session events across one analysis run's evidence.

**Scope note (read before touching this module):** this is this framework's
own *per-run* auth reconstruction — part of `NormalizedLinuxSecurityIntel`'s
output, computed fresh every time `LinuxSecurityAnalysisEngine.analyze()`
runs. It is explicitly **not** the blueprint §13 cross-evidence "Threat
Timeline" UI feature (a persisted, cross-case, all-evidence-types
reconstruction that stays Milestone M6, unbuilt) — do not conflate the two
in a future session. This module has no DB access and produces no
`TimelineEvent` rows; `core/services/linux_security_service.py` records a
`TimelineEvent(LINUX_SECURITY_FINDING_DETECTED)` per finding, not per
timeline entry.
"""

from __future__ import annotations

from core.linux_security.models import AuthenticationTimelineEntry, LinuxLogEvent

_RELEVANT_PROCESSES: frozenset[str] = frozenset(
    {"auth_failure", "auth_success", "disconnect", "session_opened", "sudo", "su"}
)


def build_timeline(events: list[LinuxLogEvent]) -> list[AuthenticationTimelineEntry]:
    """Events with no timestamp are excluded (a timeline entry with no
    ordering key is meaningless) — never raises, degrades to a shorter
    timeline instead (constitution §1.7)."""
    entries: list[AuthenticationTimelineEntry] = []
    for event in events:
        if event.process not in _RELEVANT_PROCESSES or event.timestamp is None:
            continue
        entries.append(
            AuthenticationTimelineEntry(
                timestamp=event.timestamp,
                event_type=event.process,
                user=event.user,
                ip_address=event.ip_address,
                host=event.host,
                detail=event.raw_message[:200],
            )
        )
    return sorted(entries, key=lambda entry: entry.timestamp)
