"""Unit tests for core/memory/session_memory.py."""

from __future__ import annotations

import pytest

from core.memory.interfaces import ShortTermMemory
from core.memory.session_memory import SessionMemory

pytestmark = pytest.mark.unit


def test_session_memory_satisfies_short_term_memory_protocol() -> None:
    assert isinstance(SessionMemory(), ShortTermMemory)


def test_get_returns_none_for_missing_key() -> None:
    memory = SessionMemory()
    assert memory.get("missing") is None


def test_set_then_get_round_trips() -> None:
    memory = SessionMemory()
    memory.set("evidence_draft", {"filename": "log.txt"})
    assert memory.get("evidence_draft") == {"filename": "log.txt"}


def test_delete_removes_key() -> None:
    memory = SessionMemory()
    memory.set("k", "v")
    memory.delete("k")
    assert memory.get("k") is None


def test_clear_removes_everything() -> None:
    memory = SessionMemory()
    memory.set("a", 1)
    memory.set("b", 2)
    memory.clear()
    assert memory.keys() == ()


def test_keys_lists_all_current_keys() -> None:
    memory = SessionMemory()
    memory.set("a", 1)
    memory.set("b", 2)
    assert set(memory.keys()) == {"a", "b"}
