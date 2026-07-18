"""`SessionMemory` — a concrete `ShortTermMemory` (`core/memory/interfaces.py`).

Per constitution §4.4 and ADR-0006, an agent's real short-term memory is
`CaseInvestigationState` itself; this class exists for the cases the
Protocol was already documented for but the state object doesn't cover —
a scratchpad scoped to one *process session* (e.g. one Streamlit browser
session, one API request lifecycle) rather than one case's graph run, such
as caching a user's in-progress, not-yet-submitted evidence-upload form
state. It is deliberately the simplest possible implementation: an
in-process dict, never persisted, never shared across sessions.
"""

from __future__ import annotations

from typing import Any


class SessionMemory:
    """In-process, per-session key/value scratchpad.

    Not thread-safe and not intended to be — one instance belongs to one
    session (constitution §2, "avoid global state": this is deliberately
    *not* a singleton; callers construct one per session and discard it when
    the session ends).
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def get(self, key: str) -> Any:
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()

    def keys(self) -> tuple[str, ...]:
        return tuple(self._data)
