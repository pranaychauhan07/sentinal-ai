"""Shared RFC3164-ish syslog header parsing — reused by `ssh_auth_parser.py`
and `syslog_parser.py` so the "month day time host process[pid]: message"
header regex lives in exactly one place (constitution §1.3, "never
duplicated across files").

Not a parser itself — no `BaseParser` subclass, not registered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

_SYSLOG_HEADER_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[^\[:\s]+)(\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)


@dataclass(frozen=True)
class SyslogHeader:
    timestamp: datetime | None
    host: str
    process: str
    pid: str | None
    message: str


def parse_syslog_line(line: str, *, reference_year: int | None = None) -> SyslogHeader | None:
    """Parse one RFC3164-ish syslog line. Returns `None` if `line` doesn't
    match the expected header shape at all (caller decides whether that's
    an unparsed fragment or a hard validation failure).

    Traditional syslog omits the year; `reference_year` (default: the
    current UTC year) is used to reconstruct a full timestamp. This is a
    documented, unavoidable ambiguity for this log format — a line
    timestamped near a year boundary could be misattributed by one year,
    which downstream consumers should treat as a known limitation, not a bug.
    """
    match = _SYSLOG_HEADER_RE.match(line)
    if match is None:
        return None

    year = reference_year or datetime.now(UTC).year
    timestamp: datetime | None
    try:
        timestamp = datetime.strptime(
            f"{year} {match['month']} {match['day']} {match['time']}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        timestamp = None

    return SyslogHeader(
        timestamp=timestamp,
        host=match["host"],
        process=match["process"],
        pid=match["pid"],
        message=match["message"],
    )
