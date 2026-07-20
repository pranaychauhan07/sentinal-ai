"""Suspicious Process / Reverse Shell Detection — the single, shared,
well-tested regex set every other analyzer in this package delegates to
(constitution §2, "Constants ... never duplicated across files").
`cron_analyzer.py`, `service_analyzer.py`, and `sudo_analyzer.py` all call
`find_suspicious_commands` rather than each maintaining their own copy of
these patterns; this module additionally runs the same patterns generically
over every event's raw message, regardless of category, as a catch-all
suspicious-process scan.
"""

from __future__ import annotations

import re

from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)

#: Classic reverse-shell / suspicious-execution command shapes (task-named
#: patterns). Compiled once at import time; the single source of truth for
#: this pattern set across the whole package.
REVERSE_SHELL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bnc\b.*-e\b", re.IGNORECASE),
    re.compile(r"\bncat\b.*-e\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"bash\s+-i\s*>&", re.IGNORECASE),
    re.compile(r"\bpython3?\b.*-c.*socket", re.IGNORECASE),
    re.compile(r"\bperl\b.*-e.*socket", re.IGNORECASE),
    re.compile(r"base64\s+-d.*\|\s*(sh|bash)", re.IGNORECASE),
    re.compile(r"mkfifo.*nc\b", re.IGNORECASE),
    re.compile(r"(curl|wget)\b.*\|\s*(sh|bash)\b", re.IGNORECASE),
)

#: Filesystem locations commonly abused for staging/executing dropped
#: payloads — reused by `cron_analyzer.py`/`service_analyzer.py`.
SUSPICIOUS_EXEC_PATHS: tuple[str, ...] = ("/tmp", "/dev/shm")


def find_suspicious_commands(
    text: str,
    *,
    evidence_id: LinuxLogEvent | None = None,
    line_number: int | None = None,
    subject: str = "unknown",
) -> list[LinuxSecurityCandidate]:
    """Returns one `LinuxSecurityCandidate` per distinct pattern that
    matches `text` — the single source of truth every other analyzer in
    this package calls rather than re-implementing this regex set."""
    if not text:
        return []
    candidates: list[LinuxSecurityCandidate] = []
    for pattern in REVERSE_SHELL_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        candidates.append(
            LinuxSecurityCandidate(
                category=LinuxSecurityFindingCategory.REVERSE_SHELL,
                severity=LinuxSecuritySeverity.CRITICAL,
                subject=subject,
                subject_type="host",
                title="Reverse-shell-shaped command detected",
                description=f"Matched pattern {pattern.pattern!r} in: {text[:200]}",
                line_numbers=(line_number,) if line_number is not None else (),
                context={"matched_pattern": pattern.pattern, "command": text[:500]},
            )
        )
    return candidates


def scan_generic_process_lines(events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
    """Generic, category-agnostic scan: runs `find_suspicious_commands`
    over every event's `raw_message`, regardless of which process emitted
    it — the catch-all "suspicious process" surface (task requirement),
    distinct from `cron_analyzer.py`/`service_analyzer.py`'s more targeted,
    process-specific checks."""
    candidates: list[LinuxSecurityCandidate] = []
    for event in events:
        subject = event.host or event.user or event.ip_address or "unknown"
        found = find_suspicious_commands(
            event.raw_message, line_number=event.line_number, subject=subject
        )
        for candidate in found:
            candidates.append(
                candidate.model_copy(
                    update={
                        "evidence_id": event.evidence_id,
                        "first_seen": event.timestamp or candidate.first_seen,
                        "last_seen": event.timestamp or candidate.last_seen,
                    }
                )
            )
    return candidates
