"""Shared field-name-alias heuristics for the two truly generic, schema-less
parsers (`json_evidence_parser.py`, `csv_evidence_parser.py`) — factored out
so the alias tables and lookup/coercion logic live in exactly one place
(constitution §1.3, "never duplicated across files").
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.parsers.models import Severity

TIMESTAMP_KEYS = ("timestamp", "@timestamp", "time", "ts", "event_time", "timecreated")
HOST_KEYS = ("host", "hostname", "computer", "device")
USER_KEYS = ("user", "username", "account", "user_name")
IP_KEYS = ("ip", "ip_address", "src_ip", "source_ip", "client_ip", "sourceip")
EVENT_TYPE_KEYS = ("event_type", "type", "action", "category", "eventid")
SEVERITY_KEYS = ("severity", "level", "priority")

_SEVERITY_ALIASES: dict[str, Severity] = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def first_present(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Case-insensitive lookup of the first key in `keys` present (and
    non-empty) in `item`."""
    lowered = {k.lower(): v for k, v in item.items()}
    for key in keys:
        if key in lowered and lowered[key] not in (None, ""):
            return lowered[key]
    return None


def parse_generic_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_generic_severity(value: Any) -> Severity:
    if isinstance(value, str) and value.lower() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[value.lower()]
    return Severity.INFO


def stringify(value: Any) -> str | None:
    return None if value is None else str(value)
