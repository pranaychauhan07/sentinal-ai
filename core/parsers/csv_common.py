"""Shared CSV lookup helper for the scan-report CSV parsers
(`nessus_csv_parser.py`, `openvas_csv_parser.py`) — mirrors
`core/parsers/syslog_common.py`'s "small, shared helper between sibling
parsers" precedent (constitution §2, "Utilities... live in the owning
layer's own module", never a catch-all `core/utils.py`).
"""

from __future__ import annotations


def lookup_column(row: dict[str, str], *names: str) -> str:
    """Case/whitespace-tolerant column lookup — export templates vary
    slightly in header capitalization across scanner versions. Returns the
    first non-empty match among `names`, or `""` if none match."""
    normalized = {key.strip().lower(): value for key, value in row.items() if key}
    for name in names:
        value = normalized.get(name.strip().lower())
        if value:
            return value.strip()
    return ""
