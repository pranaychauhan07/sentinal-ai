"""Cron Analysis — parses `event_type == "CRON"` (the process-name
classification `SyslogParser` assigns to cron's syslog lines) messages
shaped `(<user>) CMD (<command>)` and flags suspicious cron jobs. Reverse-
shell-shaped commands delegate to `process_detector.py`'s shared regex set
(never duplicated here, constitution §2); this module additionally flags
executable paths under `/tmp`/`/dev/shm` and `curl|wget ... | sh`/`| bash`
pipe-to-shell patterns specific to the cron shape.
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
from core.linux_security.process_detector import SUSPICIOUS_EXEC_PATHS, find_suspicious_commands

_CRON_CMD_RE = re.compile(r"\((?P<user>[^)]+)\)\s*CMD\s*\((?P<command>.*)\)\s*$")
_PIPE_TO_SHELL_RE = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash)\b", re.IGNORECASE)


class CronAnalyzer:
    """Stateless, deterministic. One instance is safe to share across a
    whole pipeline run."""

    def analyze(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        candidates: list[LinuxSecurityCandidate] = []
        for event in events:
            if event.process != "CRON":
                continue
            match = _CRON_CMD_RE.search(event.raw_message)
            if match is None:
                continue
            user = match["user"]
            command = match["command"]
            timestamp = event.timestamp or datetime.now().astimezone()
            line_numbers = (event.line_number,) if event.line_number is not None else ()

            if any(path in command for path in SUSPICIOUS_EXEC_PATHS):
                candidates.append(
                    LinuxSecurityCandidate(
                        category=LinuxSecurityFindingCategory.SUSPICIOUS_CRON,
                        severity=LinuxSecuritySeverity.HIGH,
                        subject=user,
                        subject_type="user",
                        title=f"Cron job for '{user}' executes from a world-writable path",
                        description=f"Cron command references a suspicious path: {command[:200]}",
                        evidence_id=event.evidence_id,
                        line_numbers=line_numbers,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        context={"command": command[:500]},
                    )
                )

            if _PIPE_TO_SHELL_RE.search(command):
                candidates.append(
                    LinuxSecurityCandidate(
                        category=LinuxSecurityFindingCategory.SUSPICIOUS_CRON,
                        severity=LinuxSecuritySeverity.CRITICAL,
                        subject=user,
                        subject_type="user",
                        title=f"Cron job for '{user}' pipes a download directly to a shell",
                        description=(
                            f"Cron command pipes curl/wget output to sh/bash: {command[:200]}"
                        ),
                        evidence_id=event.evidence_id,
                        line_numbers=line_numbers,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        context={"command": command[:500]},
                    )
                )

            candidates.extend(
                find_suspicious_commands(command, line_number=event.line_number, subject=user)
            )
        return candidates
