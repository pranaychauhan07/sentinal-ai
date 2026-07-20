"""Service Analysis — parses `event_type in {"systemd", "init"}` messages for
suspicious service starts. Necessarily a best-effort heuristic: standard
syslog output rarely carries a service's full unit-file content (no
`ExecStart=` line reaches syslog in the common case), so this analyzer can
only reason about what *is* commonly logged — a "Started"/"Starting" message
plus the referenced binary/service name, or the rare case where `ExecStart=`
does appear in the message verbatim (some custom logging configurations
include it). Both signals carry a real, documented false-positive risk and
are scored with correspondingly low confidence; this is honestly weaker
than the cron/sudo analyzers, which get direct command text.
"""

from __future__ import annotations

import re
from datetime import datetime

from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)
from core.linux_security.process_detector import SUSPICIOUS_EXEC_PATHS

_EXEC_START_RE = re.compile(r"ExecStart=(?P<path>\S+)")
_STARTED_RE = re.compile(r"\bStart(ed|ing)\b\s+(?P<service>.+)$", re.IGNORECASE)
_STANDARD_PATH_PREFIXES: tuple[str, ...] = ("/usr/", "/bin/", "/sbin/", "/lib/")


def _looks_nonstandard(path_or_name: str) -> bool:
    """True if `path_or_name` looks like a filesystem path but not one
    under a standard system location. A bare service name with no `/` is
    not itself suspicious (most services are named, not path-referenced) —
    only flagged when it *is* a path."""
    if "/" not in path_or_name:
        return False
    return not any(path_or_name.startswith(prefix) for prefix in _STANDARD_PATH_PREFIXES)


class ServiceAnalyzer:
    """Stateless, deterministic. One instance is safe to share across a
    whole pipeline run. See module docstring for this analyzer's honest
    false-positive-risk caveat."""

    def analyze(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        candidates: list[LinuxSecurityCandidate] = []
        for event in events:
            if event.process not in ("systemd", "init"):
                continue
            message = event.raw_message
            timestamp = event.timestamp or datetime.now().astimezone()
            line_numbers = (event.line_number,) if event.line_number is not None else ()
            subject = event.host or "unknown"

            exec_start_match = _EXEC_START_RE.search(message)
            if exec_start_match and any(
                p in exec_start_match["path"] for p in SUSPICIOUS_EXEC_PATHS
            ):
                candidates.append(
                    LinuxSecurityCandidate(
                        category=LinuxSecurityFindingCategory.SUSPICIOUS_SERVICE,
                        severity=LinuxSecuritySeverity.HIGH,
                        subject=subject,
                        subject_type="host",
                        title="Service ExecStart references a world-writable path",
                        description=f"ExecStart path looks suspicious: {exec_start_match['path']}",
                        confidence=0.8,
                        evidence_id=event.evidence_id,
                        line_numbers=line_numbers,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        context={"exec_start": exec_start_match["path"]},
                    )
                )
                continue

            started_match = _STARTED_RE.search(message)
            if started_match and _looks_nonstandard(started_match["service"].strip()):
                candidates.append(
                    LinuxSecurityCandidate(
                        category=LinuxSecurityFindingCategory.SUSPICIOUS_SERVICE,
                        severity=LinuxSecuritySeverity.LOW,
                        subject=subject,
                        subject_type="host",
                        title="Service started from a non-standard path",
                        description=(
                            f"Started/Starting message references a non-standard path: "
                            f"{started_match['service'].strip()[:200]} "
                            f"(low-confidence heuristic — see module docstring)."
                        ),
                        confidence=0.4,
                        evidence_id=event.evidence_id,
                        line_numbers=line_numbers,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        context={"service": started_match["service"].strip()[:200]},
                    )
                )
        return candidates
