"""Sudo Activity Analyzer — regexes the `sudo` syslog message shape out of
`LinuxLogEvent.raw_message` for events where `process == "sudo"` (the
process-name classification `SyslogParser` already assigned).

Flags: sensitive-file access, shell-escape commands (delegating the shared
reverse-shell/shell-escape pattern set to `process_detector.py`, never
duplicating it), running as root for a command that looks like an
interactive shell escape, and repeated sudo authentication failures (the
same sliding-window primitive `ssh_auth_analyzer.py` uses, reimplemented
locally to keep this module independently testable without importing a
sibling analyzer's private helper — a small, documented duplication, same
precedent `core.vulnerabilities.scoring`'s own module docstring accepts for
its severity-weight table).
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta

from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)
from core.linux_security.process_detector import find_suspicious_commands

DEFAULT_SUDO_FAILURE_THRESHOLD = 3
DEFAULT_SUDO_FAILURE_WINDOW_MINUTES = 10

#: `<user> : TTY=<tty> ; PWD=<pwd> ; USER=<runas> ; COMMAND=<command>` — the
#: canonical sudo syslog line shape (task-named regex).
_SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*"
    r"(?:.*?TTY=(?P<tty>\S+?)\s*;\s*)?"
    r"(?:.*?PWD=(?P<pwd>\S+?)\s*;\s*)?"
    r".*?USER=(?P<runas>\S+?)\s*;\s*COMMAND=(?P<command>.*)$"
)
_SUDO_AUTH_FAILURE_RE = re.compile(
    r"pam_unix\(sudo:auth\):\s*authentication failure.*?\buser=(?P<user>\S+)"
)

_SENSITIVE_FILES: tuple[str, ...] = ("/etc/shadow", "/etc/passwd", "/etc/sudoers")
_SHELL_ESCAPE_TOKENS: tuple[str, ...] = ("bash", "/bin/sh", " sh ", "nc ", "python -c")


def _looks_like_shell_escape(command: str) -> bool:
    lowered = f" {command.lower()} "
    return any(token in lowered for token in _SHELL_ESCAPE_TOKENS)


class SudoActivityAnalyzer:
    """Stateless, deterministic. One instance is safe to share across a
    whole pipeline run."""

    def __init__(
        self,
        *,
        failure_threshold: int = DEFAULT_SUDO_FAILURE_THRESHOLD,
        failure_window_minutes: int = DEFAULT_SUDO_FAILURE_WINDOW_MINUTES,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._failure_window = timedelta(minutes=failure_window_minutes)

    def analyze(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        candidates: list[LinuxSecurityCandidate] = []
        failures_by_user: dict[str, list[LinuxLogEvent]] = defaultdict(list)

        for event in events:
            if event.process != "sudo":
                continue

            command_match = _SUDO_COMMAND_RE.match(event.raw_message)
            if command_match is not None:
                candidates.extend(self._candidates_for_command(event, command_match))
                continue

            failure_match = _SUDO_AUTH_FAILURE_RE.search(event.raw_message)
            if failure_match is not None and event.timestamp is not None:
                failures_by_user[failure_match["user"]].append(event)

        for user, user_events in failures_by_user.items():
            timestamps = sorted(e.timestamp for e in user_events if e.timestamp is not None)
            if len(timestamps) < self._failure_threshold:
                continue
            left = 0
            best_count = 0
            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > self._failure_window:
                    left += 1
                best_count = max(best_count, right - left + 1)
            if best_count < self._failure_threshold:
                continue
            line_numbers = tuple(e.line_number for e in user_events if e.line_number is not None)
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.SUDO_ABUSE,
                    severity=LinuxSecuritySeverity.MEDIUM,
                    subject=user,
                    subject_type="user",
                    title=f"Repeated sudo authentication failures for '{user}'",
                    description=(
                        f"{best_count} sudo authentication failure(s) for '{user}' within "
                        f"{self._failure_window}."
                    ),
                    occurrence_count=best_count,
                    evidence_id=user_events[0].evidence_id,
                    line_numbers=line_numbers,
                    first_seen=timestamps[0],
                    last_seen=timestamps[-1],
                    context={"reason": "repeated_auth_failure"},
                )
            )
        return candidates

    def _candidates_for_command(
        self, event: LinuxLogEvent, match: re.Match[str]
    ) -> list[LinuxSecurityCandidate]:
        user = match["user"]
        runas = match["runas"]
        command = match["command"]
        candidates: list[LinuxSecurityCandidate] = []
        line_numbers = (event.line_number,) if event.line_number is not None else ()
        timestamp = event.timestamp or datetime.now().astimezone()

        if any(sensitive in command for sensitive in _SENSITIVE_FILES):
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.SUDO_ABUSE,
                    severity=LinuxSecuritySeverity.HIGH,
                    subject=user,
                    subject_type="user",
                    title=f"'{user}' accessed a sensitive file via sudo",
                    description=f"sudo command touched a sensitive file: {command[:200]}",
                    evidence_id=event.evidence_id,
                    line_numbers=line_numbers,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    context={"command": command[:500], "runas": runas},
                )
            )

        if runas == "root" and _looks_like_shell_escape(command):
            candidates.append(
                LinuxSecurityCandidate(
                    category=LinuxSecurityFindingCategory.SUDO_ABUSE,
                    severity=LinuxSecuritySeverity.HIGH,
                    subject=user,
                    subject_type="user",
                    title=f"'{user}' escaped to a root shell via sudo",
                    description=(
                        f"sudo command run as root looks like a shell escape: {command[:200]}"
                    ),
                    evidence_id=event.evidence_id,
                    line_numbers=line_numbers,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    context={"command": command[:500], "runas": runas, "reason": "shell_escape"},
                )
            )

        candidates.extend(
            find_suspicious_commands(command, line_number=event.line_number, subject=user)
        )
        return candidates
