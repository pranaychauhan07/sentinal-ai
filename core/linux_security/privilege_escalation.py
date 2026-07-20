"""Privilege Escalation Detector — parses account-management syslog events
(`useradd`/`adduser`, `userdel`/`deluser`, `passwd`, `usermod`, `su`) into
typed candidates, plus a combined, higher-confidence "new user immediately
followed by a privileged-group add" multi-step pattern.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)

DEFAULT_ESCALATION_CHAIN_WINDOW_MINUTES = 15

_NEW_USER_RE = re.compile(r"new user:\s*name=(?P<user>[^,]+)")
_USERDEL_RE = re.compile(r"delete user\s*['\"]?(?P<user>\S+?)['\"]?\s*$", re.IGNORECASE)
_PASSWORD_CHANGED_RE = re.compile(r"password changed for\s*(?P<user>\S+)", re.IGNORECASE)
_USERMOD_GROUP_RE = re.compile(r"add\s*'(?P<user>[^']+)'\s*to\s*group\s*'(?P<group>[^']+)'")
_SU_ROOT_RE = re.compile(r"session opened for user root by\s*\(?(?P<by_user>\S+)?", re.IGNORECASE)

_PRIVILEGED_GROUPS: frozenset[str] = frozenset({"sudo", "wheel", "admin"})
_USER_ADD_PROCESSES = frozenset({"useradd", "adduser"})
_USER_DEL_PROCESSES = frozenset({"userdel", "deluser"})


class PrivilegeEscalationDetector:
    """Stateless, deterministic. One instance is safe to share across a
    whole pipeline run."""

    def __init__(
        self, *, escalation_chain_window_minutes: int = DEFAULT_ESCALATION_CHAIN_WINDOW_MINUTES
    ) -> None:
        self._chain_window = timedelta(minutes=escalation_chain_window_minutes)

    def analyze(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        candidates: list[LinuxSecurityCandidate] = []
        new_user_events: dict[str, LinuxLogEvent] = {}
        group_escalation_events: list[tuple[str, LinuxLogEvent]] = []

        for event in events:
            process = event.process or ""
            message = event.raw_message

            if process in _USER_ADD_PROCESSES:
                match = _NEW_USER_RE.search(message)
                user = match["user"].strip() if match else (event.user or "unknown")
                new_user_events[user] = event
                candidates.append(
                    self._candidate(
                        event,
                        LinuxSecurityFindingCategory.NEW_USER,
                        LinuxSecuritySeverity.LOW,
                        user,
                        f"New user account created: '{user}'.",
                    )
                )

            elif process in _USER_DEL_PROCESSES:
                match = _USERDEL_RE.search(message)
                user = match["user"] if match else (event.user or "unknown")
                candidates.append(
                    self._candidate(
                        event,
                        LinuxSecurityFindingCategory.USER_DELETION,
                        LinuxSecuritySeverity.LOW,
                        user,
                        f"User account deleted: '{user}'.",
                    )
                )

            elif process == "passwd":
                match = _PASSWORD_CHANGED_RE.search(message)
                if match:
                    user = match["user"]
                    candidates.append(
                        self._candidate(
                            event,
                            LinuxSecurityFindingCategory.PASSWORD_CHANGE,
                            LinuxSecuritySeverity.INFO,
                            user,
                            f"Password changed for '{user}'.",
                        )
                    )

            elif process == "usermod":
                match = _USERMOD_GROUP_RE.search(message)
                if match and match["group"].lower() in _PRIVILEGED_GROUPS:
                    user = match["user"]
                    group_escalation_events.append((user, event))
                    candidates.append(
                        self._candidate(
                            event,
                            LinuxSecurityFindingCategory.PRIVILEGE_ESCALATION,
                            LinuxSecuritySeverity.HIGH,
                            user,
                            f"'{user}' added to privileged group '{match['group']}'.",
                            context={"group": match["group"]},
                        )
                    )

            elif process == "su":
                match = _SU_ROOT_RE.search(message)
                if match:
                    by_user = match["by_user"] or "unknown"
                    candidates.append(
                        self._candidate(
                            event,
                            LinuxSecurityFindingCategory.UNAUTHORIZED_ACCOUNT_ACTIVITY,
                            LinuxSecuritySeverity.MEDIUM,
                            by_user,
                            f"'{by_user}' switched to root via su.",
                            subject_type="user",
                        )
                    )

        for user, escalation_event in group_escalation_events:
            new_user_event = new_user_events.get(user)
            if new_user_event is None:
                continue
            if new_user_event.timestamp is None or escalation_event.timestamp is None:
                continue
            delta = escalation_event.timestamp - new_user_event.timestamp
            if timedelta(0) <= delta <= self._chain_window:
                candidates.append(
                    LinuxSecurityCandidate(
                        category=LinuxSecurityFindingCategory.PRIVILEGE_ESCALATION,
                        severity=LinuxSecuritySeverity.CRITICAL,
                        subject=user,
                        subject_type="user",
                        title=f"New account '{user}' immediately escalated to a privileged group",
                        description=(
                            f"'{user}' was created and added to a privileged group within "
                            f"{self._chain_window} — a real, higher-confidence multi-step "
                            f"privilege-escalation pattern."
                        ),
                        confidence=0.95,
                        evidence_id=escalation_event.evidence_id,
                        line_numbers=tuple(
                            ln
                            for ln in (new_user_event.line_number, escalation_event.line_number)
                            if ln is not None
                        ),
                        first_seen=new_user_event.timestamp,
                        last_seen=escalation_event.timestamp,
                        context={"pattern": "new_user_then_group_escalation"},
                    )
                )
        return candidates

    def _candidate(
        self,
        event: LinuxLogEvent,
        category: LinuxSecurityFindingCategory,
        severity: LinuxSecuritySeverity,
        subject: str,
        description: str,
        *,
        subject_type: str = "user",
        context: dict[str, object] | None = None,
    ) -> LinuxSecurityCandidate:
        timestamp = event.timestamp or datetime.now().astimezone()
        return LinuxSecurityCandidate(
            category=category,
            severity=severity,
            subject=subject,
            subject_type=subject_type,
            title=description,
            description=description,
            evidence_id=event.evidence_id,
            line_numbers=(event.line_number,) if event.line_number is not None else (),
            first_seen=timestamp,
            last_seen=timestamp,
            context=context or {},
        )
